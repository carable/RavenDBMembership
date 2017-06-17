using System;
using System.Collections.Generic;
using System.Configuration.Provider;
using System.Linq;
using System.Web.Security;
using Raven.Abstractions.Exceptions;
using Raven.Client;
using Microsoft.Practices.ServiceLocation;
using System.Collections.Specialized;
using RavenDBMembership.Services;

namespace RavenDBMembership.Provider
{
    public class RavenDBMembershipProvider : MembershipProvider, IConfiguration
    {
        private string _providerName = "RavenDBMembership";
        private IDocumentStore documentStore;
        private int _minRequiredPasswordLength = 7;

        public IDocumentStore DocumentStore
        {
            get
            {
                if (documentStore == null)
                {
                    throw new NullReferenceException("The DocumentStore is not set. Please set the DocumentStore or make sure that the Common Service Locator can find the IDocumentStore and call Initialize on this provider.");
                }
                return this.documentStore;
            }
            set { this.documentStore = value; }
        }

        public override string ApplicationName
        {
            get; set;
        }

        public override void Initialize(string name, NameValueCollection config)
        {
            if (config.Keys.Cast<string>().Contains("minRequiredPasswordLength"))
            {
                _minRequiredPasswordLength = int.Parse(config["minRequiredPasswordLength"]);
            }

            // Try to find an IDocumentStore via Common Service Locator. 
            try
            {
                var locator = ServiceLocator.Current;
                if (locator != null)
                {
                    this.DocumentStore = locator.GetInstance<IDocumentStore>();
                }
            }
            catch (NullReferenceException) // Swallow Nullreference expection that occurs when there is no current service locator.
            {
            }

            _providerName = name;

            base.Initialize(name, config);
        }

        public override bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            using (var session = this.DocumentStore.OpenSession())
            {
                var success = Service(session).ChangePassword(username, oldPassword, newPassword);
                session.SaveChanges();
                return success;
            }
        }

        public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
        {
            throw new NotImplementedException();
        }

        public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
        {
            using (var session = this.DocumentStore.OpenSession())
            {
                session.Advanced.UseOptimisticConcurrency = true;

                try
                {
                    var user = Service(session).CreateUser(username, password, email, out status);
                    if (status == MembershipCreateStatus.Success)
                    {
                        session.SaveChanges();
                        return new MembershipUser(_providerName, username, user.Id, email, null, null, true, false, user.DateCreated,
                            new DateTime(1900, 1, 1), new DateTime(1900, 1, 1), DateTime.Now, new DateTime(1900, 1, 1));
                    }
                    else
                    {
                        return null;
                    }
                }
                catch (ConcurrencyException e)
                {
                    status = InterpretConcurrencyException(username, email, e);
                }
                catch (Exception ex)
                {
                    // TODO: log exception properly
                    Console.WriteLine(ex.ToString());
                    status = MembershipCreateStatus.ProviderError;
                }
            }
            return null;
        }

        MembershipCreateStatus InterpretConcurrencyException(string username, string email, ConcurrencyException e)
        {
            MembershipCreateStatus status;
            if (e.Message.Contains("username/" + username))
                status = MembershipCreateStatus.DuplicateUserName;
            else if (e.Message.Contains("email/" + email))
                status = MembershipCreateStatus.DuplicateEmail;
            else
            {
                status = MembershipCreateStatus.ProviderError;
            }
            return status;
        }

        public override bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            using (var session = this.DocumentStore.OpenSession())
            {
                try
                {
                    if (Service(session).DeleteUser(username, deleteAllRelatedData))
                    {
                        session.SaveChanges();
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    // TODO: log exception properly
                    Console.WriteLine(ex.ToString());
                }
                return false;
            }
        }

        public override bool EnablePasswordReset
        {
            get { return true; }
        }

        public override bool EnablePasswordRetrieval
        {
            get { return false; }
        }

        public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            return FindUsers(u => u.Email.Contains(emailToMatch), pageIndex, pageSize, out totalRecords);
        }

        public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            return FindUsers(u => u.Username.Contains(usernameToMatch), pageIndex, pageSize, out totalRecords);
        }

        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            return FindUsers(null, pageIndex, pageSize, out totalRecords);
        }

        public override int GetNumberOfUsersOnline()
        {
            throw new NotImplementedException();
        }

        public override string GetPassword(string username, string answer)
        {
            throw new NotImplementedException();
        }

        public override MembershipUser GetUser(string username, bool userIsOnline)
        {
            using (var session = this.DocumentStore.OpenSession())
            {
                var q = from u in session.Query<User>().Customize(c => c.WaitForNonStaleResultsAsOfNow())
                        where u.Username == username && u.ApplicationName == this.ApplicationName
                        select u;
                var user = q.SingleOrDefault();
                if (user != null)
                {
                    return UserToMembershipUser(user);
                }
                return null;
            }
        }

        public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
        {
            using (var session = this.DocumentStore.OpenSession())
            {
                var user = session.Load<User>(providerUserKey.ToString());
                if (user != null)
                {
                    return UserToMembershipUser(user);
                }
                return null;
            }
        }

        public override string GetUserNameByEmail(string email)
        {
            using (var session = this.DocumentStore.OpenSession())
            {
                var q = from u in session.Query<User>()
                        where u.Email == email && u.ApplicationName == this.ApplicationName
                        select u.Username;
                return q.SingleOrDefault();
            }
        }

        public override int MaxInvalidPasswordAttempts
        {
            get { return 10; }
        }

        public override int MinRequiredNonAlphanumericCharacters
        {
            get { return 0; }
        }

        public override int MinRequiredPasswordLength { get { return _minRequiredPasswordLength; } }

        public override int PasswordAttemptWindow
        {
            get { return 5; }
        }

        public override MembershipPasswordFormat PasswordFormat
        {
            get { return MembershipPasswordFormat.Hashed; }
        }

        public override string PasswordStrengthRegularExpression
        {
            get { return String.Empty; }
        }

        public override bool RequiresQuestionAndAnswer
        {
            get { return false; }
        }

        public override bool RequiresUniqueEmail
        {
            get { return false; }
        }

        Action<ValidatePasswordEventArgs> IConfiguration.OnValidatingPassword { get { return this.OnValidatingPassword; } }

        public override string ResetPassword(string username, string answer)
        {
            using (var session = this.DocumentStore.OpenSession())
            {
                try
                {
                    var q = from u in session.Query<User>()
                            where u.Username == username && u.ApplicationName == this.ApplicationName
                            select u;
                    var user = q.SingleOrDefault();
                    if (user == null)
                    {
                        throw new Exception("The user to reset the password for could not be found.");
                    }
                    var newPassword = Membership.GeneratePassword(8, 2);
                    user.PasswordSalt = PasswordUtil.CreateRandomSalt();
                    user.PasswordHash = PasswordUtil.HashPassword(newPassword, user.PasswordSalt);

                    session.SaveChanges();
                    return newPassword;
                }
                catch (Exception ex)
                {
                    // TODO: log exception properly
                    Console.WriteLine(ex.ToString());
                    throw;
                }
            }
        }

        public override bool UnlockUser(string userName)
        {
            throw new NotImplementedException();
        }

        public override void UpdateUser(MembershipUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            string username = user.UserName;
            SecUtility.CheckParameter(ref username, true, true, true, 0x100, "UserName");

            string email = user.Email;
            SecUtility.CheckParameter(ref email, this.RequiresUniqueEmail, this.RequiresUniqueEmail, false, 0x100, "Email");
            user.Email = email;

            using (var session = this.DocumentStore.OpenSession())
            {
                session.Advanced.UseOptimisticConcurrency = true;

                try
                {
                    var q = from u in session.Query<User>()
                            where u.Username == user.UserName && u.ApplicationName == this.ApplicationName
                            select u;
                    var dbUser = q.SingleOrDefault();
                    if (dbUser == null)
                    {
                        throw new Exception("The user to update could not be found.");
                    }

                    var originalEmail = dbUser.Email;

                    if (originalEmail != user.Email)
                    {
                        session.Delete(session.Load<ReservationForUniqueFieldValue>("email/" + dbUser.Email));
                        session.Store(new ReservationForUniqueFieldValue { Id = "email/" + user.Email });
                    }

                    dbUser.Username = user.UserName;
                    dbUser.Email = user.Email;
                    dbUser.DateCreated = user.CreationDate;
                    dbUser.DateLastLogin = user.LastLoginDate;

                    session.SaveChanges();
                }
                catch (ConcurrencyException ex)
                {
                    var status = InterpretConcurrencyException(user.UserName, user.Email, ex);

                    if (status == MembershipCreateStatus.DuplicateEmail)
                        throw new ProviderException("The E-mail supplied is invalid.");
                    else
                        throw;
                }
            }
        }

        private RavenDBUserValidations Service(IDocumentSession session)
        {
            return new RavenDBUserValidations(new RavenDBUserService(session, this), this);
        }

        public override bool ValidateUser(string username, string password)
        {
            var updateLastLogin = true;

            return CheckPassword(username, password, updateLastLogin);
        }

        public bool CheckPassword(string username, string password, bool updateLastLogin)
        {
            username = username.Trim();
            password = password.Trim();

            using (var session = this.DocumentStore.OpenSession())
            {
                var success = Service(session).CheckPassword(username, password, updateLastLogin);
                session.SaveChanges(); // we might want to log things (in the service) when a user tries to log on
                return success;
            }
        }

        private MembershipUserCollection FindUsers(Func<User, bool> predicate, int pageIndex, int pageSize, out int totalRecords)
        {
            var membershipUsers = new MembershipUserCollection();
            using (var session = this.DocumentStore.OpenSession())
            {
                var q = from u in session.Query<User>()
                        where u.ApplicationName == this.ApplicationName
                        select u;
                IEnumerable<User> results;
                if (predicate != null)
                {
                    results = q.Where(predicate);
                }
                else
                {
                    results = q;
                }
                totalRecords = results.Count();
                var pagedUsers = results.Skip(pageIndex * pageSize).Take(pageSize);
                foreach (var user in pagedUsers)
                {
                    membershipUsers.Add(UserToMembershipUser(user));
                }
            }
            return membershipUsers;
        }

        private MembershipUser UserToMembershipUser(User user)
        {
            return new RavenDBMembershipUser(_providerName, user.Username, user.Id, user.Email, null, null, true, false
                , user.DateCreated, user.DateLastLogin.HasValue ? user.DateLastLogin.Value : new DateTime(1900, 1, 1), new DateTime(1900, 1, 1), new DateTime(1900, 1, 1), new DateTime(1900, 1, 1));
        }
    }
}
