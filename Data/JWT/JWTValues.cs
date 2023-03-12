namespace JWT.Data.JWT
{
    public class JWTValues
    {
        public string? Key { get; set; }
        public string? Issuer { get; set; }
        public string? Audience { get; set; }
        public double DurationInDays { get; set; }
    }
}
