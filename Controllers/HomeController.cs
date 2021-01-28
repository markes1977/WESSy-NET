using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using WinWESSY.Models;
using Amazon.DynamoDBv2.Model;
using Amazon.DynamoDBv2;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using System.Net.Http;
using System.Net.Http.Headers;
using Newtonsoft.Json;
using System.Threading;
using Nager.PublicSuffix;
using Texnomic.NMap.Scanner;
using OWASPZAPDotNetAPI;

namespace WinWESSY.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Submit(SubmitModel model)
        {
            ResultModel rm = new ResultModel();
            if (ModelState.IsValid)
            {
                string builditback = "";
                string myreturn = SubmitScanner(model.AppName, model.URL);
                rm.detailedScore = myreturn;
                string[] holdArray = rm.detailedScore.Split("|");
                int lastElement = holdArray.Length-1;
                ViewBag.Message = holdArray[0];
                for (int y = 1; y < lastElement; y++)
                {
                    if (y == (lastElement-1))
                        builditback += holdArray[y];
                    else
                        builditback += holdArray[y] + " | ";
                }
                ViewBag.Message1 = builditback;
            }  
            return View("Result");
        }

        public string SubmitScanner(string myAppName, string myURL)
        {
            int appScore = 0;
            bool azFlag = false;
            bool gcpFlag = false;
            bool wafFlag = false;
            string myInsertSTR = myAppName + "-" + DateTime.Now.ToString("MM-dd-yyyy--HH:mm:ss");
            string strDBINSERT = "";

            try
            {
                //Secrets Manager
                var smClient = new AmazonSecretsManagerClient();
                var request = new GetSecretValueRequest
                {
                    SecretId = "Wappalyzer_API"
                };
                GetSecretValueResponse response = smClient.GetSecretValueAsync(request).Result;
                string wapAPIKEYHolder = response.SecretString;
                Dictionary<string, string> getMYKEY = JsonConvert.DeserializeObject<Dictionary<string, string>>(wapAPIKEYHolder);

                //Wappalyzer
                HttpClient wapClient = new HttpClient();
                wapClient.BaseAddress = new Uri("https://api.wappalyzer.com/crawl/v2/");
                string urlParameters = "?urls=" + myURL + "&recursive=false";
                wapClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                wapClient.DefaultRequestHeaders.Add("x-api-key", getMYKEY["x-api-key"]);
                HttpResponseMessage wapResponse = wapClient.GetAsync(urlParameters).Result;
                if ((int)wapResponse.StatusCode == 200)
                {
                    string wapRESULTS = wapResponse.Content.ReadAsStringAsync().Result;

                    //////SERVER Platforms//////////////////////////////////////////////
                    if (wapRESULTS.Contains("Java Servlet") == true)
                    {
                        appScore -= 5;
                        strDBINSERT += "Java Servlet|";
                    }
                    else if (wapRESULTS.Contains("IIS") == true)
                    {
                        appScore -= 5;
                        strDBINSERT += "IIS|";
                    }
                    else if (wapRESULTS.Contains("ASP.NET") == true)
                    {
                        strDBINSERT += "ASP.NET|";
                        appScore -= 5;
                    }

                    //////CSP///////////////////////////////////////////////////////////
                    else if (wapRESULTS.Contains("Azure") == true)
                    {
                        azFlag = true;
                        strDBINSERT += "Azure|";
                    }
                    else if (wapRESULTS.Contains("Google web server") == true)
                    {
                        strDBINSERT += "Google web server|";
                        gcpFlag = true;
                    }

                    //////WAFs/CDN/LBs//////////////////////////////////////////////////
                    else if (wapRESULTS.Contains("Incapsula") == true)
                    {
                        strDBINSERT += "Incapsula|";
                        appScore += 15;
                        wafFlag = true;
                    }
                    else if (wapRESULTS.Contains("Cloudflare") == true)
                    {
                        strDBINSERT += "Cloudflare|";
                        appScore += 15;
                        wafFlag = true;
                    }
                    else if (wapRESULTS.Contains("Akamai") == true)
                    {
                        strDBINSERT += "Akamai|";
                        appScore += 15;
                        wafFlag = true;
                    }
                    else if (wapRESULTS.Contains("Azure CDN") == true)
                    {
                        strDBINSERT += "Azure CDN|";
                        azFlag = true;
                        appScore += 15;
                    }
                    else if (wapRESULTS.Contains("PerimeterX") == true)
                    {
                        strDBINSERT += "PerimeterX|";
                        appScore += 15;
                        wafFlag = true;
                    }
                    else if (wapRESULTS.Contains("Amazon ALB") == true)
                    {
                        strDBINSERT += "Amazon ALB|";
                        appScore += 15;
                    }
                    else if (wapRESULTS.Contains("Cloudinary") == true)
                    {
                        strDBINSERT += "Cloudinary|";
                        appScore += 15;
                    }
                    else if (wapRESULTS.Contains("Auth0") == true)
                    {
                        strDBINSERT += "Auth0|";
                        appScore += 15;
                    }
                    else if (wapRESULTS.Contains("WAF") == true)
                    {
                        strDBINSERT += "WAF|";
                        appScore += 15;
                        wafFlag = true;
                    }
                    else if (wapRESULTS.Contains("reCAPTCHA") == true)
                    {
                        strDBINSERT += "reCAPTCHA|";
                        appScore += 15;
                    }

                    //////JS Frameworks//////////////////////////////////////////////////
                    else if (wapRESULTS.Contains("Node.js") == true)
                    {
                        if (wapRESULTS.Contains("14.15") == false)
                        {
                            strDBINSERT += "NodeJS Version|";
                            appScore -= 25;
                        }
                    }
                    else if (wapRESULTS.Contains("AngularJS") == true)
                    {
                        if (wapRESULTS.Contains("1.7.2") == false)
                        {
                            strDBINSERT += "AngularJS Version|";
                            appScore -= 25;
                        }
                    }
                    else if (wapRESULTS.Contains("React") == true)
                    {
                        if (wapRESULTS.Contains("17.0") == false)
                        {
                            appScore -= 25;
                            strDBINSERT += "ReactJS Version|";
                        }
                    }
                    else if (wapRESULTS.Contains("jQuery") == true)
                    {
                        if (wapRESULTS.Contains("3.5.1") == false)
                        {
                            appScore -= 25;
                            strDBINSERT += "jQuery Version|";
                        }
                    }
                    ////Cloud Storage////////////////////////////////////////////////////
                    else if (wapRESULTS.Contains("S3") == true)
                    {
                        var awsdomainParser = new DomainParser(new WebTldRuleProvider());
                        var awsdomainInfo = awsdomainParser.Parse(myURL);
                        string awsburl = "https://" + awsdomainInfo.Domain + ".s3.amazonaws.com";
                        HttpClient awsClient = new HttpClient();
                        awsClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                        HttpResponseMessage awsResponse = awsClient.GetAsync(awsburl).Result;
                        if ((int)awsResponse.StatusCode != 404)
                        {
                            appScore -= 35;
                            strDBINSERT += "S3|";
                        }
                    }
                    else if (azFlag)
                    {
                        var azdomainParser = new DomainParser(new WebTldRuleProvider());
                        var azdomainInfo = azdomainParser.Parse(myURL);
                        string azbloburl = "https://" + azdomainInfo.Domain + ".blob.core.windows.net/";
                        HttpClient azClient = new HttpClient();
                        azClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                        HttpResponseMessage azResponse = azClient.GetAsync(azbloburl).Result;
                        if ((int)azResponse.StatusCode != 404)
                        {
                            appScore -= 20;
                            strDBINSERT += "AzureBLOB|";
                        }
                    }
                    else if (gcpFlag)
                    {
                        var gcpdomainParser = new DomainParser(new WebTldRuleProvider());
                        var gcpdomainInfo = gcpdomainParser.Parse(myURL);
                        string gcpburl = "https://www.googleapis.com/storage/v1/b/" + gcpdomainInfo.Domain;
                        HttpClient gcpClient = new HttpClient();
                        gcpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                        HttpResponseMessage gcpResponse = gcpClient.GetAsync(gcpburl).Result;
                        if ((int)gcpResponse.StatusCode != 404)
                        {
                            appScore -= 35;
                            strDBINSERT += "GCPBucket|";
                        }
                    }
                }

                //SSLLABS
                Chilkat.Http http = new Chilkat.Http();
                Chilkat.Cert sslCert = http.GetServerSslCert(myURL, 443);
                if (sslCert != null)
                {
                    if (sslCert.Expired)
                    {
                        appScore -= 15;
                        strDBINSERT += "expired-cert|";
                    }

                    if (sslCert.CertVersion == 1)
                    {
                        appScore -= 15;
                        strDBINSERT += "legacy-cert|";
                    }

                    if (sslCert.GetSpkiFingerprint("md2", "base64").ToString() != null)
                    {
                        appScore -= 15;
                        strDBINSERT += "md2|";
                    }
                    else if (sslCert.GetSpkiFingerprint("sha1", "base64").ToString() != null)
                    {
                        appScore -= 15;
                        strDBINSERT += "sha1|";
                    }
                    else if (sslCert.GetSpkiFingerprint("haval", "base64").ToString() != null)
                    {
                        appScore -= 15;
                        strDBINSERT += "haval|";
                    }
                    else if (sslCert.GetSpkiFingerprint("ripemd128", "base64").ToString() != null)
                    {
                        appScore -= 15;
                        strDBINSERT += "ripemd128|";
                    }
                    else if (sslCert.GetSpkiFingerprint("ripemd160", "base64").ToString() != null)
                    {
                        appScore -= 15;
                        strDBINSERT += "ripemd160|";
                    }
                }
                
                //NMAP & ZAP
                if (!wafFlag)
                {
                    //NMAP
                    var domainParser = new DomainParser(new WebTldRuleProvider());
                    var domainInfo = domainParser.Parse(myURL);
                    string nmapdomain = domainInfo.SubDomain + "." + domainInfo.Domain + "." + domainInfo.TLD;
                    var Target = new Target(nmapdomain);
                    var Scanner = new Scanner(@"C:\Nmap\nmap.exe", Target)
                    {
                        Options = new NmapOptions() { NmapFlag.TreatHostsAsOnline, { NmapFlag.TopPorts, "2" }, NmapFlag.Reason }
                    };
                    var Result = Scanner.PortScan(ScanType.Syn);
                    foreach (var Host in Result.Hosts)
                    {
                        foreach (var Ports in Host.Ports)
                        {
                            foreach (var Port in Ports.Port)
                            {
                                if (Port.PortID.Contains("21") || Port.PortID.Contains("22") || Port.PortID.Contains("23") || Port.PortID.Contains("25") || Port.PortID.Contains("446") || Port.PortID.Contains("1433") || Port.PortID.Contains("1521") || Port.PortID.Contains("3306") || Port.PortID.Contains("3389"))
                                {
                                    appScore -= 15;
                                    strDBINSERT += "Port " + Port.PortID + "|";
                                }
                            }
                        }
                    }

                    //ZAP
                    string myapikey = System.IO.File.ReadAllText(@"C:\Users\smarkey\PycharmProjects\flaskWESSY\pwessy.txt");
                    ClientApi zapi = new ClientApi("127.0.0.1", 8080, myapikey);
                    IApiResponse apiResponse = zapi.spider.scan(myURL, "", "", "", "");
                    string activeScanId = ((ApiResponseElement)apiResponse).Value;
                    Thread.Sleep(600);
                    List<Alert> alerts = zapi.GetAlerts(myURL, 0, 0, string.Empty);
                    foreach (var alert in alerts)
                    {
                        if (alert.Risk.ToString() == "High")
                        {
                            appScore -= 10;
                            strDBINSERT += "-OWASPHigh|";
                        }
                        else if (alert.Risk.ToString() == "Medium")
                        {
                            appScore -= 5;
                            strDBINSERT += "-OWASPMedium|";
                        }
                    }
                }

                //DynamoDB
                var ddbClient = new AmazonDynamoDBClient();
                var insItem = new PutItemRequest
                {
                    TableName = "tblAppScan",
                    Item = new Dictionary<string, AttributeValue>
                    {
                        { "AppKey", new AttributeValue { S = myInsertSTR }},
                        { "ScanData", new AttributeValue { S = strDBINSERT + "|" + myURL + "|" + appScore.ToString() }}
                    }
                };
                ddbClient.PutItemAsync(insItem);
            }

            catch(Exception e)
            { Console.WriteLine(e); }
            string myLetterGrade = "";
            appScore += 100;
            switch(appScore)
            {
                case int n when (n >= 75):
                    myLetterGrade = "A";
                    break;

                case int n when (n < 0):
                    myLetterGrade = "F";
                    break;

                case int n when (n >= 40 && n < 75):
                    myLetterGrade = "B";
                    break;

                case int n when (n >= 0 && n < 40):
                    myLetterGrade = "C";
                    break;

                default:
                    myLetterGrade = "F";
                    break;
            }
            string myreturn = myLetterGrade + "|" + strDBINSERT;
            return myreturn; 
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
