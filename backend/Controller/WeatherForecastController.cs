using Microsoft.AspNetCore.Mvc;
using saas_platform.Backend.Data;

namespace saas_platform.backend.Controller
{
    [ApiController]
    [Route("weatherforecast")]
    public class WeatherForecastController : ControllerBase
    {
        [HttpGet("test-db")]
        public string TestDb(
        [FromServices] PostgresDbContext db,
        [FromServices] MongoService mongo)
            {
            _ = db.Users.Count(); 
            _ = mongo;
            return "DBs connected";
        }
    }
}