using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using RestAPI.Auth.Models;
using System.IdentityModel.Tokens.Jwt;

namespace RestAPI.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class InfoController : ControllerBase
    {
       
        [HttpGet("Me")]
        [Authorize(Roles = ApplicationRoles.User)]
        public IActionResult Me()
        {
            var jwtSecurityToken = HttpContext.GetTokenAsync("Bearer", "access_token").Result;


            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(jwtSecurityToken);

            var id = token.Subject;

            return Ok(new { Subject = id, Content = "User"});
        }    
        
        [HttpGet("AdminMe")]
        [Authorize(Roles = ApplicationRoles.Admin)]
        public IActionResult AdminMe()
        {
            var jwtSecurityToken = HttpContext.GetTokenAsync("Bearer", "access_token").Result;


            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(jwtSecurityToken);

            var id = token.Subject;
        

            return Ok(new { Subject = id, Content = "Admin"});
        }
    }
}