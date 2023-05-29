using System.Security.Claims;
using AuthorizationSample.Areas.Identity;
using AuthorizationSample.Data;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace AuthorizationSample.Claims {

    public class CustomAuthenticationStateProvider : RevalidatingIdentityAuthenticationStateProvider<ApplicationUser> {
        private ClaimsPrincipal? currentUser;

        public CustomAuthenticationStateProvider(ILoggerFactory loggerFactory, IServiceScopeFactory scopeFactory, IOptions<IdentityOptions> optionsAccessor) : base(loggerFactory, scopeFactory, optionsAccessor) {
        }

        public ClaimsPrincipal CurrentUser {
            get { return currentUser ?? new(); }
            set {
                currentUser = value;
            }
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync() {
            var authState = await base.GetAuthenticationStateAsync();
            var identity = (ClaimsIdentity?) authState.User.Identity;
            if (identity == null) {
                return authState;
            }
            if (authState.User.Identity?.Name == "jonker") {
                identity.AddClaim(new Claim(ClaimTypes.Role, "Admin"));
            } else {
                identity.AddClaim(new Claim(ClaimTypes.Role, "Student"));
            }
            identity.AddClaim(new Claim("impersonate", authState.User.Identity?.Name ?? ""));
            var user = new ClaimsPrincipal(identity);
            currentUser = user;
            return new AuthenticationState(user);
        }

        public Task<AuthenticationState> Impersonate(string user) {
            var identity = (ClaimsIdentity?) CurrentUser.Identity;
            if (identity == null) {
                return Task.FromResult(new AuthenticationState(CurrentUser));
            }
            var impersonateClaim = identity.FindFirst(c => c.Type == "impersonate");
            if (impersonateClaim != null) {
                identity.RemoveClaim(impersonateClaim);
            }
            identity.AddClaim(new Claim("impersonate", user));
            currentUser = new ClaimsPrincipal(identity);
            return Task.FromResult(new AuthenticationState(CurrentUser));
        }

        public IdentityUser PullManually() {
            var identityUser = new IdentityUser("jonker");
            identityUser.Email = "bryanjonker@gmail.com";
            return identityUser;
        }
    }
}