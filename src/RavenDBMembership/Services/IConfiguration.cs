using System;
using System.Web.Security;

namespace RavenDBMembership.Services
{
    public interface IConfiguration
    {
        Action<ValidatePasswordEventArgs> OnValidatingPassword { get; }
        bool RequiresUniqueEmail { get; }
        int MinRequiredPasswordLength { get; }
        int MinRequiredNonAlphanumericCharacters { get; }
        string PasswordStrengthRegularExpression { get; }
        string ApplicationName { get; }
    }
}