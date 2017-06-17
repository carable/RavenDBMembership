using System.Web.Security;

namespace RavenDBMembership.Services
{
    public interface IUserService
    {
        /// <summary>
        /// 
        /// </summary>
        User CreateUser(string username, string password, string email, out MembershipCreateStatus status);
        /// <summary>
        /// 
        /// </summary>
        /// <param name="username"></param>
        /// <param name="oldPassword"></param>
        /// <param name="newPassword"></param>
        /// <returns></returns>
        bool ChangePassword(string username, string oldPassword, string newPassword);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="username"></param>
        /// <param name="deleteAllRelatedData"></param>
        /// <returns></returns>
        bool DeleteUser(string username, bool deleteAllRelatedData);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="updateLastLogin"></param>
        /// <returns></returns>
        bool CheckPassword(string username, string password, bool updateLastLogin);
    }

}