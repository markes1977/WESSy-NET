using System.ComponentModel.DataAnnotations;

namespace WinWESSY.Models
{
    public class SubmitModel
    {
        [Required(ErrorMessage = "A unique application name is required, ex: Blahv430.")]
        [RegularExpression("^[a-zA-Z0-9]*$", ErrorMessage = "Only letters and numbers allowed.")]
        public string AppName { get; set; }
        
        [Url]
        [Required]
        public string URL { get; set; }

        public bool cbCrypto { get; set; }

        public bool cbSCA { get; set; }

        public bool cbOWASP { get; set; }

        public bool cbNMAP { get; set; }

        public bool cbCloudStorage { get; set; }

    }
}
