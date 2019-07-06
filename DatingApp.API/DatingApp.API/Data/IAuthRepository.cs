using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using DatingApp.API.Models;

namespace DatingApp.API.Data
{
    public interface IAuthRepository
    {
        //rejestracja usera
        Task<User> Register(User user, string password);

        //login
        Task<User> Login(string username, string password);

        //czy istenieje
        Task<bool> UserExists(string username);
    }
}
