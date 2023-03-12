using Microsoft.AspNetCore.Identity;

namespace JWT.Data.JWT
{
    public class AddDatabaseItem
    {
        public static async Task AddRoll(IServiceProvider provider,List<string> roles)
        {
            var scopFactory = provider.GetRequiredService<IServiceScopeFactory>();
            var role = scopFactory.CreateScope();
            var ro = role.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            foreach(string roleName in roles)
            {
                if (!await ro.RoleExistsAsync(roleName))
                {
                    IdentityRole rol = new IdentityRole { Name = roleName, NormalizedName = roleName };
                    await ro.CreateAsync(rol);
                }
            }            
        }
        public static async Task AddAdmin(IServiceProvider provider,string email)
        {
            var scopFactory = provider.GetRequiredService<IServiceScopeFactory>();
            var user = scopFactory.CreateScope();
            var us = user.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();            
                if (await us.FindByEmailAsync(email) == null)
                {
                    IdentityUser rol = new IdentityUser { 
                        Email = email,
                        UserName = email,
                        EmailConfirmed = true,                        
                    };
                    await us.CreateAsync(rol,"Qweasd12#");
                }
            
        }
    }
}
