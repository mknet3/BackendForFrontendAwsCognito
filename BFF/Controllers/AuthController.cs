using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace BackendForFrontend.Controllers
{
    public class AuthController : Controller
    {
        public ActionResult Login(string returnUrl = "http://localhost:5555")
        {
            return new ChallengeResult("AWSCognito", new AuthenticationProperties
            {
                RedirectUri = returnUrl
            });
        }

        [Authorize]
        public async Task<ActionResult> Logout()
        {
            await HttpContext.SignOutAsync();

            return new SignOutResult("AWSCognito", new AuthenticationProperties
            {
                RedirectUri = "/"
            });
        }


        public ActionResult GetUser()
        {
            if (User?.Identity?.IsAuthenticated != true)
            {
                return Json(new {isAuthenticated = false});
            }

            var claims = ((ClaimsIdentity) this.User.Identity).Claims.Select(c =>
                    new {type = c.Type, value = c.Value})
                .ToArray();

            return Json(new
            {
                isAuthenticated = true,
                claims
            });

        }
    }
}