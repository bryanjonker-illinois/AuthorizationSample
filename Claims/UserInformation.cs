namespace AuthorizationSample.Claims {

    public class UserInformation {
        public string EDWID { get; set; } = "";
        public string Email { get; set; } = "";
        public string IEIN { get; set; } = "";
        public bool IsAdmin { get; set; } = false;
        public string Username { get; set; } = "";
    }
}