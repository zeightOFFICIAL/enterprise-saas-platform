using MongoDB.Driver;
using saas_platform.Backend.Entities;

namespace saas_platform.Backend.Data
{
    public class MongoService
    {
        private readonly IMongoCollection<Workflow> _workflows;

        public MongoService()
        {
            var client = new MongoClient("mongodb://saasuser:saaspassword@localhost:27017");
            var database = client.GetDatabase("saasdb");
            _workflows = database.GetCollection<Workflow>("workflows");
        }
    }
}