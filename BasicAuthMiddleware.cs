using Microsoft.Owin;
using System;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace AMC.Owin
{
    public class BasicAuthMiddleware : OwinMiddleware
    {
        public const string AuthMode = "Basic";
        
        public BasicAuthMiddleware(OwinMiddleware next)
            : base(next)
        {

        }

        public BasicAuthMiddleware(OwinMiddleware next, Func<string, string, Task<IIdentity>> validationCallback)
            : this(next)
        {
            IndentityVerificationCallback = validationCallback;
        }

        Func<string, string, Task<IIdentity>> IndentityVerificationCallback
        {
            get;
            set;
        }

        public override async Task Invoke(IOwinContext context)
        {
            var request = context.Request;
            var response = context.Response;

            response.OnSendingHeaders(o =>
            {
                var rResp = (IOwinResponse)o;

                if (rResp.StatusCode == 401)
                {
                    rResp.Headers["WWW-Authenticate"] = AuthMode;
                }
            }, response);

            var header = request.Headers["Authorization"];

            if (!string.IsNullOrWhiteSpace(header))
            {
                var authHeader = AuthenticationHeaderValue.Parse(header);

                if (AuthMode.Equals(authHeader.Scheme, StringComparison.OrdinalIgnoreCase))
                {
                    var parameter = Encoding.UTF8.GetString(Convert.FromBase64String(authHeader.Parameter));
                    var parts = parameter.Split(':');

                    var userName = parts[0];
                    var password = parts[1];

                    if (IndentityVerificationCallback != null)
                    {
                        var identity = await IndentityVerificationCallback.Invoke(userName, password);
                        if (identity != null)
                        {
                            request.User = new ClaimsPrincipal(identity);
                        }
                    }
                }
            }

            await Next.Invoke(context);
        }
    }
}
