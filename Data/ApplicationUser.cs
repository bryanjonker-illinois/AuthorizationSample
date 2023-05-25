using Microsoft.AspNetCore.Identity;

namespace AuthorizationSample.Data {

    // pulled from https://www.mvc.tech/blog/blazoridentityuser/
    public class ApplicationUser : IdentityUser {
        public string Impersonate { get; set; } = "";
    }
}