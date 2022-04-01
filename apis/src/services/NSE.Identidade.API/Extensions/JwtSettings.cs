namespace NSE.Identidade.API.Extensions
{
    public class JwtSettings
    {
        public string? ValidAudience { get; set; }
        public string? ValidIssuer { get; set; }
        public string Secret { get; set; }
        public double ExpirationHours { get; set; }
    }
}
