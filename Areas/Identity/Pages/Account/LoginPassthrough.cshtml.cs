using System.Security.Claims;
using AuthorizationSample.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AuthorizationSample.Areas.Identity.Pages.Account {

    public class LoginPassthroughModel : PageModel {
        private readonly CustomAuthenticationStateProvider _customAuthenticationStateProvider;
        private readonly ILogger<LoginPassthroughModel> _logger;
        private readonly SignInManager<IdentityUser> _signInManager;

        public LoginPassthroughModel(SignInManager<IdentityUser> signInManager, AuthenticationStateProvider custom, ILogger<LoginPassthroughModel> logger) {
            _signInManager = signInManager;
            _customAuthenticationStateProvider = (CustomAuthenticationStateProvider) custom;
            _logger = logger;
        }

        public async Task<IActionResult> OnGet(string guid = "") {
            var newResult = _customAuthenticationStateProvider.PullManually(guid);
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
            await _signInManager.SignInWithClaimsAsync(newResult, true, new List<Claim>());
            return LocalRedirect(Url.Content("~/"));
        }
    }
}