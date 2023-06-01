namespace AuthorizationSample.Claims {

    public static class MockDatabase {

        public static List<UserInformation> Users = new List<UserInformation> {
            new UserInformation { Email = "bryanjonker@gmail.com", Username = "jonker", IsAdmin = true },
            new UserInformation { Email = "student1@gmail.com", Username = "student1", EDWID = "ED1", IEIN = "0001" },
            new UserInformation { Email = "student2@gmail.com", Username = "student2", EDWID = "ED2", IEIN = "0002" }
        };

        public static UserInformation? Get(string info) => Users.FirstOrDefault(u => u.Email == info || u.Username == info);

        public static UserInformation? GetFromOldSystem(string guid) => guid == "student" ? Get("student1") : Get("jonker");
    }
}