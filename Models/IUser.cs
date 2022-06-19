namespace WebService.JwtAuthentication.Models
{
	public interface IUser
	{
		string Id { get; }
		string Email { get; }

		Task DeleteToken(string ip);
	}
}
