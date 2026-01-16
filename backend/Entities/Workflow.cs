using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace saas_platform.Backend.Entities
{
    public class Workflow
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string Id { get; set; }
        public Guid TenantId { get; set; }
        public string ConfigJson { get; set; }
        public string Status { get; set; }
    }
}