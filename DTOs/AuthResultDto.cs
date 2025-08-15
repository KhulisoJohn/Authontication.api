namespace Authentication.DTOs
{
    public class AuthResultDto
    {
        public string Token { get; set; }
        public string UserId { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
        public string? Bio { get; set; }

        public AuthResultDto(string token, string userId, string userName, string email, string? bio)
        {
            Token = token;
            UserId = userId;      
            UserName = userName;
            Email = email;
            Bio = bio;
        }
    }
}
