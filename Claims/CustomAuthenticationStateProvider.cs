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
            // normally, this would be pulling from a database based on user information.
            if (!identity.Claims.Any(c => c.Type == ClaimTypes.Role)) {
                var userFromDatabase = MockDatabase.Get(authState.User.Identity?.Name ?? "");
                if (userFromDatabase != null) {
                    if (userFromDatabase.IsAdmin) {
                        identity.AddClaim(new Claim(ClaimTypes.Role, "Admin"));
                    } else {
                        identity.AddClaim(new Claim(ClaimTypes.Role, "Student"));
                        identity.AddClaim(new Claim(ClaimConstants.IeinClaimType, userFromDatabase.IEIN));
                        identity.AddClaim(new Claim(ClaimConstants.EdwClaimType, userFromDatabase.EDWID));
                    }
                }
            }
            var user = new ClaimsPrincipal(identity);
            currentUser = user;
            return new AuthenticationState(user);
        }

        public Task<AuthenticationState> Impersonate(string user) {
            var identity = (ClaimsIdentity?) CurrentUser.Identity;
            if (identity == null) {
                return Task.FromResult(new AuthenticationState(CurrentUser));
            }
            _ = RemoveImpersonation();
            identity.AddClaim(new Claim(ClaimConstants.ImpersonateClaimType, user));
            var userFromDatabase = MockDatabase.Get(user);
            if (userFromDatabase != null) {
                identity.AddClaim(new Claim(ClaimConstants.IeinClaimType, userFromDatabase.IEIN));
                identity.AddClaim(new Claim(ClaimConstants.EdwClaimType, userFromDatabase.EDWID));
            }
            currentUser = new ClaimsPrincipal(identity);
            return Task.FromResult(new AuthenticationState(CurrentUser));
        }

        public IdentityUser PullManually(string guid) {
            // normally, this would be pulling from a database based on a GUID.
            var userFromDatabase = MockDatabase.GetFromOldSystem(guid);
            return userFromDatabase == null ? new IdentityUser() : new IdentityUser(userFromDatabase.Username) { Email = userFromDatabase.Email };
        }

        public Task<AuthenticationState> RemoveImpersonation() {
            var identity = (ClaimsIdentity?) CurrentUser.Identity;
            if (identity == null) {
                return Task.FromResult(new AuthenticationState(CurrentUser));
            }
            var impersonateClaim = identity.FindFirst(c => c.Type == ClaimConstants.ImpersonateClaimType);
            if (impersonateClaim != null) {
                identity.RemoveClaim(impersonateClaim);
                var ieinClaim = identity.FindFirst(c => c.Type == ClaimConstants.IeinClaimType);
                if (ieinClaim != null) {
                    identity.RemoveClaim(ieinClaim);
                }
                var edwidClaim = identity.FindFirst(c => c.Type == ClaimConstants.EdwClaimType);
                if (edwidClaim != null) {
                    identity.RemoveClaim(edwidClaim);
                }
            }
            currentUser = new ClaimsPrincipal(identity);
            return Task.FromResult(new AuthenticationState(CurrentUser));
        }
    }
}