using System.Security.Claims;

namespace AuthorizationSample.Claims {

    public static class ImpersonateCheck {

        public static string ImpersonateId(IEnumerable<Claim> claims) {
            var impersonateString = GetImpersonateString(claims);
            return (string.IsNullOrWhiteSpace(impersonateString) ? "" : impersonateString + " / ") + claims.SingleOrDefault(c => c.Type == ClaimTypes.Name)?.Value ?? "";
        }

        public static string ImpersonateMessage(IEnumerable<Claim> claims) {
            var impersonateString = GetImpersonateString(claims);
            return string.IsNullOrWhiteSpace(impersonateString) ? "no impersonation" : "impersonating " + impersonateString;
        }

        private static string? GetImpersonateString(IEnumerable<Claim> claims) => claims.SingleOrDefault(c => c.Type == ClaimConstants.ImpersonateClaimType)?.Value;
    }
}