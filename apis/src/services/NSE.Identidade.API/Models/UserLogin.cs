using System.ComponentModel.DataAnnotations;

namespace NSE.Identidade.API.Models
{
    public class UserLogin
    {
        [Required(ErrorMessage = "O campo email é obrigatório")]
        [EmailAddress(ErrorMessage = "O campo email está em um formato inválido")]
        public string? Email { get; set; }

        [Required(ErrorMessage = "O campo senha é obrigatório")]
        [StringLength(100, ErrorMessage = "O campo senha precisa ter entre {2} e {1} caracteres", MinimumLength = 6)]
        public string? Password { get; set; }
    }
}
