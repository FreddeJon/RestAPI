using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace RestAPI.Auth.Interfaces
{
    public interface IJwtGeneration
    {
        JwtSecurityToken GenerateJWTToken(List<Claim> claims);
    }

}
