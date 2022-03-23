using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using RestAPI.Auth;
using RestAPI.Auth.Models;

namespace RestAPI.Seeds
{
    public static class Seed
    {
        public static async void Initialize(IServiceProvider serviceProvider)
        {
            using var scope = serviceProvider.CreateScope();
            var userManager = scope.ServiceProvider.GetService<UserManager<ApplicationUser>>();
            var roleManager = scope.ServiceProvider.GetService<RoleManager<IdentityRole>>();
            var context = scope.ServiceProvider.GetService<ApplicationDbContext>();
            var configuration = serviceProvider.GetService<IConfiguration>();

            if (userManager is null || roleManager is null || context is null || configuration is null)
            {
                throw new ArgumentNullException();
            }


            context!.Database.Migrate();


            await SeedRoles(roleManager);

            await SeedAdmin(userManager, configuration);
        }
        private static async Task SeedRoles(RoleManager<IdentityRole> roleManager)
        {
            if ( !await roleManager.RoleExistsAsync(ApplicationRoles.User))
            {
                await roleManager.CreateAsync(new IdentityRole(ApplicationRoles.User));
            }
            if (!await roleManager.RoleExistsAsync(ApplicationRoles.Admin))
            {
                await roleManager.CreateAsync(new IdentityRole(ApplicationRoles.Admin));
            }
            return;
        }

        private static async Task SeedAdmin(UserManager<ApplicationUser> userManager, IConfiguration configuration)
        {
            var email = configuration!["ADMIN:EMAIL"] ?? "admin@admin";
            var userName = configuration!["ADMIN:USERNAME"] ?? "admin";
            var password = configuration!["ADMIN:PASSWORD"] ?? "admin";

            var admin = await userManager.FindByEmailAsync(email);

            if (admin is not null) return;

            var adminUser = new ApplicationUser()
            {
                Email = email,
                UserName = userName
            };

            var created = await userManager.CreateAsync(adminUser, password);


            if (created.Succeeded)
            {
                var confirmationToken = userManager.GenerateEmailConfirmationTokenAsync(adminUser).Result;
                await userManager.ConfirmEmailAsync(adminUser, confirmationToken);
                await userManager.AddToRolesAsync(adminUser, new List<string>() { ApplicationRoles.Admin, ApplicationRoles.User });
            }

            return;
        }
    }
}
