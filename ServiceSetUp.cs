﻿using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace WebService.JwtAuthentication
{
	public static class ServiceSetUp
	{
		public static IServiceCollection AddJwtAuth(this IServiceCollection services, SymmetricSecurityKey Key)
		{
			services.AddAuthentication(options =>
			{
				options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
				options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
			}).AddJwtBearer(options =>
			{
				options.RequireHttpsMetadata = false;
				options.SaveToken = true;
				options.TokenValidationParameters = new TokenValidationParameters()
				{
					ValidateIssuerSigningKey = true,
					IssuerSigningKey = Key,
					ValidateIssuer = false,
					ValidateAudience = false
				};
			});

			return services;
		}
	}
}
