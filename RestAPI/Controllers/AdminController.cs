using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using RestAPI.Auth;
using RestAPI.Auth.Models;

namespace RestAPI.Controllers
{
    [Authorize(Roles = ApplicationRoles.Admin)]
    [Route("api/[controller]")]
    [ApiController]
    public class AdminController : ControllerBase
    {
        private readonly ApplicationDbContext _dbContext;

        public AdminController(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }
        [HttpGet("Users")]
        public async Task<IActionResult> GetAllUsers()
        {
           return Ok(_dbContext.Users.Select(x => x).ToList());
        }
    }
}
