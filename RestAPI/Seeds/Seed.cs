using Microsoft.AspNetCore.Identity;
using RestAPI.Auth;
using RestAPI.Auth.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RestAPI.Seeds
{
    public static class Seed
    {
        public static async void Initialize(IServiceProvider serviceProvider)
        {
            using (var scope = serviceProvider.CreateScope())
            {
                var userManager = scope.ServiceProvider.GetService<UserManager<ApplicationUser>>();
                var roleManager = scope.ServiceProvider.GetService<RoleManager<IdentityRole>>();
                var context = scope.ServiceProvider.GetService<ApplicationDbContext>();

                if (userManager is null || roleManager is null || context is null) return;

                context!.Database.EnsureCreated();

                if (!roleManager!.RoleExistsAsync(UserRoles.User).Result)
                {
                    await roleManager!.CreateAsync(new IdentityRole(UserRoles.User));
                }
                if (!roleManager!.RoleExistsAsync(UserRoles.Admin).Result)
                {
                    await roleManager!.CreateAsync(new IdentityRole(UserRoles.Admin));
                }

                var email = "admin@admin";
                var password = "admin";

                var admin = await userManager.FindByEmailAsync(email);

                if (admin is not null) return;

                var newAdmin = new ApplicationUser()
                {
                    Email = email,
                    UserName = "admin"
                };

               await userManager.CreateAsync(newAdmin, password);

               await userManager.AddToRolesAsync(newAdmin, new List<string>() { UserRoles.Admin, UserRoles.User });
            }
        }
        private static async void SeedRoles(RoleManager<IdentityRole> roleManager)
        {
            if (!roleManager!.RoleExistsAsync(UserRoles.User).Result)
            {
                await roleManager!.CreateAsync(new IdentityRole(UserRoles.User));
            }
            if (!roleManager!.RoleExistsAsync(UserRoles.Admin).Result)
            {
                await roleManager!.CreateAsync(new IdentityRole(UserRoles.Admin));
            }
        }

        private static async void SeedAdmin( UserManager<ApplicationUser> userManager)
        {
            var email = "admin@admin";
            var password = "admin";

            var admin = await userManager.FindByEmailAsync(email);

            if (admin is not null) return;

            var newAdmin = new ApplicationUser()
            {
                Email = email,
                UserName = "admin"
            };

             userManager.CreateAsync(newAdmin, password).GetAwaiter();

             userManager.AddToRolesAsync(newAdmin, new List<string>() { UserRoles.Admin, UserRoles.User }).GetAwaiter();
        }
    }
}
