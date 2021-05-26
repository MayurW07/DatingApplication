using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
  public class AccountController : BaseApiController
  {
    private readonly DataContext _context;
    private readonly ITokenService _tokenService;

    public AccountController(DataContext context,ITokenService tokenService)
    {
      _context = context;
      _tokenService = tokenService;
    }

    [HttpPost("register")]
    public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
    {
      if (await UserExists(registerDto.username)) return BadRequest("UserName already Taken.");
      using var hmac = new HMACSHA512();
      var user = new AppUser()
      {
        UserName = registerDto.username.ToLower(),
        PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.password)),
        PasswordSalt = hmac.Key
      };

      _context.Users.Add(user);
      await _context.SaveChangesAsync();

      return new UserDto{
          Username=user.UserName,
          Token=_tokenService.CreateToken(user)
      };
    }

    [HttpPost("Login")]
    public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
    {
      var user = await _context.Users.SingleOrDefaultAsync(XE => XE.UserName == loginDto.username.ToLower());

      if (user == null) return Unauthorized("Invalid User");

      using var hmac = new HMACSHA512(user.PasswordSalt);
      var computedhash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.password));

      for (int i = 0; i < computedhash.Length; i++)
      {
        if (computedhash[i] != user.PasswordHash[i]) return Unauthorized("Access Denied, Invalid Password");
      }

      return new UserDto{
          Username=user.UserName,
          Token=_tokenService.CreateToken(user)
      };
    }

    private async Task<bool> UserExists(string Username)
    {
      return await _context.Users.AnyAsync(XE => XE.UserName == Username.ToLower());
    }

  }
}