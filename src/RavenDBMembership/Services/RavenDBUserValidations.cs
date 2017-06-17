using RavenDBMembership.Provider;
using RavenDBMembership.UserStrings;
using System;
using System.Text.RegularExpressions;
using System.Web.Security;

namespace RavenDBMembership.Services
{
    public class RavenDBUserValidations:IUserService
    {
        private readonly IUserService _service;
        private readonly IConfiguration conf;
        private Action<ValidatePasswordEventArgs> OnValidatingPassword { get { return conf.OnValidatingPassword; } }

        public RavenDBUserValidations(IUserService service, IConfiguration conf)
        {
            _service = service;
            this.conf = conf;
        }

        public User CreateUser(string username, string password, string email, out MembershipCreateStatus status)
        {
            if (!SecUtility.ValidateParameter(ref password, true, true, false, 0x80))
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }
            if (!SecUtility.ValidateParameter(ref username, true, true, true, 0x100))
            {
                status = MembershipCreateStatus.InvalidUserName;
                return null;
            }
            if (!SecUtility.ValidateParameter(ref email, conf.RequiresUniqueEmail, conf.RequiresUniqueEmail, false, 0x100))
            {
                status = MembershipCreateStatus.InvalidEmail;
                return null;
            }
            if (password.Length < conf.MinRequiredPasswordLength)
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }
            int num = 0;
            for (int i = 0; i < password.Length; i++)
            {
                if (!char.IsLetterOrDigit(password, i))
                {
                    num++;
                }
            }
            if (num < conf.MinRequiredNonAlphanumericCharacters)
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }
            if ((conf.PasswordStrengthRegularExpression.Length > 0) && !Regex.IsMatch(password, conf.PasswordStrengthRegularExpression))
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }
            ValidatePasswordEventArgs e = new ValidatePasswordEventArgs(username, password, true);
            this.OnValidatingPassword(e);
            if (e.Cancel)
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            return _service.CreateUser(username, password, email, out status);
        }

        public bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            SecUtility.CheckParameter(ref username, true, true, true, 0x100, "username");
            SecUtility.CheckParameter(ref oldPassword, true, true, false, 0x80, "oldPassword");
            SecUtility.CheckParameter(ref newPassword, true, true, false, 0x80, "newPassword");

            if (!CheckPassword(username, oldPassword, false))
            {
                return false;
            }
            if (newPassword.Length < conf.MinRequiredPasswordLength)
            {
                throw new ArgumentException("Password is shorter than the minimum " + conf.MinRequiredPasswordLength, "newPassword");
            }
            int num3 = 0;
            for (int i = 0; i < newPassword.Length; i++)
            {
                if (!char.IsLetterOrDigit(newPassword, i))
                {
                    num3++;
                }
            }
            if (num3 < conf.MinRequiredNonAlphanumericCharacters)
            {
                throw new ArgumentException(
                    SR.Password_need_more_non_alpha_numeric_chars_1.WithParameters(conf.MinRequiredNonAlphanumericCharacters),
                    "newPassword");
            }
            if ((conf.PasswordStrengthRegularExpression.Length > 0) && !Regex.IsMatch(newPassword, conf.PasswordStrengthRegularExpression))
            {
                throw new ArgumentException(SR.Password_does_not_match_regular_expression.WithParameters(),
                    "newPassword");
            }
            ValidatePasswordEventArgs e = new ValidatePasswordEventArgs(username, newPassword, false);
            this.OnValidatingPassword(e);
            if (e.Cancel)
            {
                if (e.FailureInformation != null)
                {
                    throw e.FailureInformation;
                }
                throw new ArgumentException(SR.Membership_Custom_Password_Validation_Failure.WithParameters(), "newPassword");
            }

            return _service.ChangePassword(username, oldPassword, newPassword);
        }

        public bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            SecUtility.CheckParameter(ref username, true, true, true, 0x100, "username");

            return _service.DeleteUser(username, deleteAllRelatedData);
        }

        public bool CheckPassword(string username, string password, bool updateLastLogin)
        {
            return _service.CheckPassword(username, password, updateLastLogin);
        }
    }
}
