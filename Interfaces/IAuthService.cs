using Authentication.DTOs;
using System.Threading.Tasks;

namespace Authentication.Interfaces
{
    public interface IAuthService
    {
        Task<AuthResultDto> RegisterAsync(UserRegisterDto dto);
        Task<AuthResultDto> LoginAsync(UserLoginDto dto);
    }
}
