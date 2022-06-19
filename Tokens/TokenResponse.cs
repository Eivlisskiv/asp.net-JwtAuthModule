using WebService.JwtAuthentication.Models;

namespace WebService.JwtAuthentication.Tokens
{
	public class TokenResponse
	{
#pragma warning disable IDE1006 // Naming Styles
        public string user_id { get; set; }
        public string access_token { get; set; }
        public string refresh_token { get; set; }
        public DateTime expiration_date { get; set; }

#pragma warning restore IDE1006 // Naming Styles

        public TokenResponse(IUser user, string token, IRefreshToken rtoken)
        {
            user_id = user.Id;
            access_token = token;
            refresh_token = rtoken.Token;
            expiration_date = rtoken.Expires;
        }
    }
}
