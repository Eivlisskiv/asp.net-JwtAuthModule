using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using WebService.JwtAuthentication.Models;
using WebService.JwtAuthentication.Tokens;

namespace WebService.JwtAuthentication
{
	public abstract class AuthenticationHandler
    {
        const int EXPIRATION_MINUTES = 2;

        private readonly JwtSecurityTokenHandler handler;

        protected abstract SymmetricSecurityKey Key { get; }

        public AuthenticationHandler()
        {
            handler = new JwtSecurityTokenHandler();
        }

        protected abstract Task<(bool, IUser)> TryAuthenticate(AuthCredentials creds);

        protected abstract IRefreshToken CreateRefreshToken(IUser user, string ip);

        protected abstract Task<IRefreshToken> LoadRefreshToken(string refreshToken, string ip);

        protected abstract Task<IUser> LoadUser(string user);

        public async Task<TokenResponse?> Authenticate(AuthCredentials creds, string ip)
        {
            (bool verified, IUser user) = await TryAuthenticate(creds);
            if (!verified) return null;

            SecurityToken token = CreateToken(user);

            IRefreshToken rtoken = CreateRefreshToken(user, ip);
            await user.DeleteToken(ip);
            await rtoken.Save();
            return new TokenResponse(user, handler.WriteToken(token), rtoken);
        }

        public async Task<TokenResponse?> Refresh_Token(string refreshToken, string ip)
        {
            IRefreshToken rtoken = await LoadRefreshToken(refreshToken, ip);

            if (rtoken == null) return null;

            if (rtoken.Expires < DateTime.UtcNow)
            {
                await rtoken.Delete();
                return null;
            }

            IUser user = await LoadUser(rtoken.User);
            SecurityToken token = CreateToken(user);

            return new TokenResponse(user, handler.WriteToken(token), rtoken);
        }

		public SecurityToken CreateToken(IUser user)
        {
            SecurityTokenDescriptor descriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[] {
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim(ClaimTypes.Email, user.Email)
                }),
                Expires = DateTime.UtcNow.AddMinutes(EXPIRATION_MINUTES),
                SigningCredentials = new SigningCredentials(Key, SecurityAlgorithms.HmacSha256Signature)
            };

            return handler.CreateToken(descriptor);
        }
    }
}
