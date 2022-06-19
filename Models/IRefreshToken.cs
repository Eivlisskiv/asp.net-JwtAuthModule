namespace WebService.JwtAuthentication.Models
{
	public interface IRefreshToken
	{
		string Token { get; }
		DateTime Expires { get; }
		string User { get; }

		Task Delete();
		Task Save();
	}
}
