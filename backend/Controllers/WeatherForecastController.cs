using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using saas_platform.backend.Data;

namespace saas_platform.backend.Controllers
{
    [ApiController]
    [Route("weatherforecast")]
    public class WeatherForecastController : ControllerBase
    {
        [HttpGet("test-db")]
        [Authorize]
        public string TestDb(
        [FromServices] PostgresDbContext db,
        [FromServices] MongoService mongo)
            {
            _ = db.Users.Count(); 
            _ = mongo;
            return "DBs connected";
        }

        [HttpGet("test-db-admin")]
        [Authorize(Roles = "Admin")]
        public string TestDbAdmin(
        [FromServices] PostgresDbContext db,
        [FromServices] MongoService mongo)
        {
            _ = db.Users.Count();
            _ = mongo;
            return "DBs connected by admin";
        }
    }
}