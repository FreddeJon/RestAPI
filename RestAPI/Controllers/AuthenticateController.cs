using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using RestAPI.Auth.Interfaces;
using RestAPI.Auth.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace RestAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IAuthService _authService;
        private readonly IConfiguration _configuration;

        public AuthenticateController(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IAuthService authService,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _authService = authService;
            _configuration = configuration;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginModel model)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);


            var user = await _userManager.FindByEmailAsync(model.Email);


            if (!await _authService.ValidateUser(user, model.Password!)) return Unauthorized();


            var claims = await _authService.GetClaimsForUser(user);


            var token = _authService.CreateToken(claims);
            var refreshToken = _authService.GenerateRefreshToken();


            _ = int.TryParse(_configuration["JWT:RefreshTokenValidityInDays"], out int refreshTokenValidityInDays);

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshTokenValidityInDays);

           _ = await _userManager.UpdateAsync(user);


            return Ok(new
            {
                AccessToken = new JwtSecurityTokenHandler().WriteToken(token),
                RefreshToken = refreshToken,
                Expiration = token.ValidTo
            });

        }


        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new { Status = "Error", Message = "User already exists!" });

            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };

            var result = await _userManager.CreateAsync(user, model.Password);


            if (!result.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new { Status = "Error", Message = "User creation failed! Please check user details and try again.", Errors = result.Errors.Select(x => x.Description).ToList() });
            }

            await _userManager.AddToRoleAsync(user, ApplicationRoles.User);

            return Ok(new { Status = "Success", Message = "User created successfully!" });
        }

        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> RefreshToken(TokenModel tokenModel)
        {


            try
            {
                if (tokenModel is null || string.IsNullOrEmpty(tokenModel.AccessToken) || string.IsNullOrEmpty(tokenModel.RefreshToken))
                {
                    return BadRequest("Invalid client request");
                }

                var handler = new JwtSecurityTokenHandler();
                var token = handler.ReadJwtToken(tokenModel.AccessToken);


                if (token == null)
                {
                    throw new ArgumentNullException();
                }

                var user = await _userManager.FindByIdAsync(token.Subject);

                if (user == null || user.RefreshToken != tokenModel.RefreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
                {
                    throw new ArgumentNullException();
                }

                var newAccessToken = _authService.CreateToken(token.Claims.ToList());
                var newRefreshToken = _authService.GenerateRefreshToken();

                user.RefreshToken = newRefreshToken;
                await _userManager.UpdateAsync(user);

                return new ObjectResult(new
                {
                    accessToken = new JwtSecurityTokenHandler().WriteToken(newAccessToken),
                    refreshToken = newRefreshToken,
                    expiration = newAccessToken.ValidTo
                });
            }
            catch (Exception)
            {

                return BadRequest("Invalid access token or refresh token");
            }





        }
    }

}