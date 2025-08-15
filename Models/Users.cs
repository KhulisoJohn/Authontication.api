using Microsoft.AspNetCore.Identity;

namespace Authentication.Models;

public class User : IdentityUser<Guid>
{
    public string Bio { get; set; } = string.Empty;
}
