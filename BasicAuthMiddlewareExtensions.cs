using System;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.Owin.Extensions;
using Owin;

namespace AMC.Owin
{
    public static class BasicAuthMiddlewareExtensions
    {
        public static IAppBuilder UseBasicAuthentication(this IAppBuilder app, Func<string /* username */, string /* password */, Task<IIdentity>> validationCallback)
        {
            app.Use<BasicAuthMiddleware>(validationCallback);
            return app.UseStageMarker(PipelineStage.Authenticate);
        }
    }
}
