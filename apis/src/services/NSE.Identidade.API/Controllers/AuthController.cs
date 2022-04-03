using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NSE.Identidade.API.Extensions;
using NSE.Identidade.API.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace NSE.Identidade.API.Controllers
{
    [ApiController]
    [Route("v1/auth")]
    public class AuthController : MainController
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JwtSettings _jwtSettings;

        public AuthController(SignInManager<IdentityUser> signInManager, 
                                UserManager<IdentityUser> userManager,
                                IOptions<JwtSettings> options)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _jwtSettings = options.Value;
        }

        [HttpPost("register")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400, Type = typeof(IdentityResult))]
        public async Task<IActionResult> Register(UserRegistration userRegistration)
        {
            if(!ModelState.IsValid) return CustomResponse(ModelState);

            var user = new IdentityUser
            {
                Email = userRegistration.Email,
                UserName = userRegistration.Email,
                EmailConfirmed = true
            };

            var result  = await _userManager.CreateAsync(user, userRegistration.Password);

            if (result.Succeeded)
            {
                return CustomResponse(await GenerateJwt(user.Email));
            }

            foreach (var error in result.Errors)
            {
                AddOperationError(error.Description);
            }

            return CustomResponse();
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserLogin userLogin)
        {
            if (!ModelState.IsValid) return CustomResponse(ModelState);

            var result = await _signInManager.PasswordSignInAsync(userLogin.Email, userLogin.Password, false, true);

            if (result.Succeeded)
                return CustomResponse(await GenerateJwt(userLogin.Email));

            if (result.IsLockedOut)
            {
                AddOperationError("Usuário temporariamente bloqueado por tentativas inválidas");
                return CustomResponse();
            }
                
            AddOperationError("Usuário ou senha incorretos");
            return CustomResponse();
        }

        private async Task<IList<Claim>> GetClaims(IdentityUser? user)
        {
            if(user == null)
                throw new ArgumentNullException(nameof(user));


            var roles = await _userManager.GetRolesAsync(user);
            var claims = await _userManager.GetClaimsAsync(user);

            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, user.Id));
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));

            roles ??= new List<string>();
            foreach (var userRole in roles)
            {
                claims.Add(new Claim("role", userRole));
            }

            return claims;
        }

        private string EncodeToken(ClaimsIdentity claims)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret));

            var token = tokenHandler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = _jwtSettings.ValidIssuer,
                Audience = _jwtSettings.ValidAudience,
                Subject = claims,
                Expires = DateTime.UtcNow.AddHours(_jwtSettings.ExpirationHours),
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature)
            });

            return tokenHandler.WriteToken(token);
        }

        private async Task<UserLoginResponse> GenerateJwt(string? email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            var claims = await GetClaims(user);

            return new UserLoginResponse
            {
                AccessToken = EncodeToken(new ClaimsIdentity(claims)),
                ExpiresIn = TimeSpan.FromHours(_jwtSettings.ExpirationHours).TotalSeconds,
                UserToken = new UserToken
                {
                    Id = user.Id,
                    Email = user.Email,
                    Claims = claims.Select(x => new UserClaim { Type = x.Type, Value = x.Value })
                }
            };
        }
    }
}
