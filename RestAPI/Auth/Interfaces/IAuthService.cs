using RestAPI.Auth.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace RestAPI.Auth.Interfaces
{
    public interface IAuthService
    {
        Task<bool> ValidateUser(ApplicationUser user, string password);
        JwtSecurityToken CreateToken(List<Claim> claims);
        Task<List<Claim>> GetClaimsForUser(ApplicationUser user);
        string GenerateRefreshToken();
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);

    }
}
