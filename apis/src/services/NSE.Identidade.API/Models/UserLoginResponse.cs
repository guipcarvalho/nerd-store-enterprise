using System.ComponentModel.DataAnnotations;

namespace NSE.Identidade.API.Models
{
    public class UserLoginResponse
    {
        public string? AccessToken { get; set; }
        public double ExpiresIn { get; set; }
        public UserToken? UserToken { get; set; }
    }
}
