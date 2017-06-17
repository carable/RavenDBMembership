using Raven.Client;
using System;
using System.Linq;
using System.Web.Security;

namespace RavenDBMembership.Services
{
    public class RavenDBUserService : IUserService
    {
        private readonly IDocumentSession session;
        private readonly IConfiguration conf;

        public RavenDBUserService(IDocumentSession session, IConfiguration conf)
        {
            this.conf = conf;
            this.session = session;
        }

        public bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            username = username.Trim();

            var q = from u in session.Query<User>()
                    where u.Username == username && u.ApplicationName == conf.ApplicationName
                    select u;
            var user = q.SingleOrDefault();
            if (user == null || user.PasswordHash != PasswordUtil.HashPassword(oldPassword, user.PasswordSalt))
            {
                throw new MembershipPasswordException("Invalid username or old password.");
            }

            user.PasswordSalt = PasswordUtil.CreateRandomSalt();
            user.PasswordHash = PasswordUtil.HashPassword(newPassword, user.PasswordSalt);
            return true;
        }

        public bool CheckPassword(string username, string password, bool updateLastLogin)
        {
            username = username.Trim();
            password = password.Trim();

            var q = from u in session.Query<User>().Customize(c => c.WaitForNonStaleResultsAsOfNow())
                    where u.Username == username && u.ApplicationName == conf.ApplicationName
                    select u;
            var user = q.SingleOrDefault();

            if (user != null && user.PasswordHash == PasswordUtil.HashPassword(password, user.PasswordSalt))
            {
                if (updateLastLogin)
                {
                    user.DateLastLogin = DateTime.Now;
                }
                return true;
            }
            return false;
        }

        public User CreateUser(string username, string password, string email, out MembershipCreateStatus status)
        {
            if (password.Length < conf.MinRequiredPasswordLength)
                throw new MembershipCreateUserException(MembershipCreateStatus.InvalidPassword);

            ValidatePasswordEventArgs args = new ValidatePasswordEventArgs(username, password, true);
            conf.OnValidatingPassword(args);
            if (args.Cancel)
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }
            username = username.Trim();

            var user = new User();
            user.Username = username;
            password = password.Trim();
            user.PasswordSalt = PasswordUtil.CreateRandomSalt();
            user.PasswordHash = PasswordUtil.HashPassword(password, user.PasswordSalt);
            user.Email = email;
            user.ApplicationName = conf.ApplicationName;
            user.DateCreated = DateTime.Now;

            session.Store(user);
            session.Store(new ReservationForUniqueFieldValue { Id = "username/" + user.Username });
            session.Store(new ReservationForUniqueFieldValue { Id = "email/" + user.Email });


            status = MembershipCreateStatus.Success;

            return user;
        }

        public bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            var q = from u in session.Query<User>().Customize(c => c.WaitForNonStaleResultsAsOfNow())
                    where u.Username == username && u.ApplicationName == conf.ApplicationName
                    select u;
            var user = q.SingleOrDefault();
            if (user == null)
            {
                throw new NullReferenceException("The user could not be deleted.");
            }

            session.Delete(user);
            session.Delete(session.Load<ReservationForUniqueFieldValue>("username/" + user.Username));
            session.Delete(session.Load<ReservationForUniqueFieldValue>("email/" + user.Email));

            return true;
        }
    }
}
