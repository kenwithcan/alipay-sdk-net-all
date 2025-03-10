/*
 * 支付宝开放平台API
 *
 * 支付宝开放平台v3协议文档
 *
 * The version of the OpenAPI document: 2025-02-19
 * Generated by: https://github.com/openapitools/openapi-generator.git
 */


using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.IO;
using System.Runtime.Serialization;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System.ComponentModel.DataAnnotations;
using OpenAPIDateConverter = AlipaySDKNet.OpenAPI.Client.OpenAPIDateConverter;

namespace AlipaySDKNet.OpenAPI.Model
{
    /// <summary>
    /// AgentScheduleLog
    /// </summary>
    [DataContract(Name = "AgentScheduleLog")]
    public partial class AgentScheduleLog : IEquatable<AgentScheduleLog>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AgentScheduleLog" /> class.
        /// </summary>
        /// <param name="agentId">客服id.</param>
        /// <param name="agentName">客服名称.</param>
        /// <param name="createTime">状态变更发生时间,采用UTC时间，按照ISO8601标准表示，格式为：yyyy-MM-dd&#39;T&#39;HH:mm:ss&#39;Z&#39;.</param>
        /// <param name="duration">状态持续时长,单位秒.</param>
        /// <param name="endTime">状态变更结束时间,采用UTC时间，按照ISO8601标准表示，格式为：yyyy-MM-dd&#39;T&#39;HH:mm:ss&#39;Z&#39;.</param>
        /// <param name="externalUserNo">isv或商户系统中对应的客服工号.</param>
        /// <param name="id">客服状态变更流水id.</param>
        /// <param name="lastStatus">变更前状态.</param>
        /// <param name="startTime">状态变更开始时间,采用UTC时间，按照ISO8601标准表示，格式为：yyyy-MM-dd&#39;T&#39;HH:mm:ss&#39;Z&#39;.</param>
        /// <param name="status">变更后状态.</param>
        public AgentScheduleLog(string agentId = default(string), string agentName = default(string), string createTime = default(string), int duration = default(int), string endTime = default(string), string externalUserNo = default(string), string id = default(string), string lastStatus = default(string), string startTime = default(string), string status = default(string))
        {
            this.AgentId = agentId;
            this.AgentName = agentName;
            this.CreateTime = createTime;
            this.Duration = duration;
            this.EndTime = endTime;
            this.ExternalUserNo = externalUserNo;
            this.Id = id;
            this.LastStatus = lastStatus;
            this.StartTime = startTime;
            this.Status = status;
        }

        /// <summary>
        /// 客服id
        /// </summary>
        /// <value>客服id</value>
        [DataMember(Name = "agent_id", EmitDefaultValue = false)]
        public string AgentId { get; set; }

        /// <summary>
        /// 客服名称
        /// </summary>
        /// <value>客服名称</value>
        [DataMember(Name = "agent_name", EmitDefaultValue = false)]
        public string AgentName { get; set; }

        /// <summary>
        /// 状态变更发生时间,采用UTC时间，按照ISO8601标准表示，格式为：yyyy-MM-dd&#39;T&#39;HH:mm:ss&#39;Z&#39;
        /// </summary>
        /// <value>状态变更发生时间,采用UTC时间，按照ISO8601标准表示，格式为：yyyy-MM-dd&#39;T&#39;HH:mm:ss&#39;Z&#39;</value>
        [DataMember(Name = "create_time", EmitDefaultValue = false)]
        public string CreateTime { get; set; }

        /// <summary>
        /// 状态持续时长,单位秒
        /// </summary>
        /// <value>状态持续时长,单位秒</value>
        [DataMember(Name = "duration", EmitDefaultValue = false)]
        public int Duration { get; set; }

        /// <summary>
        /// 状态变更结束时间,采用UTC时间，按照ISO8601标准表示，格式为：yyyy-MM-dd&#39;T&#39;HH:mm:ss&#39;Z&#39;
        /// </summary>
        /// <value>状态变更结束时间,采用UTC时间，按照ISO8601标准表示，格式为：yyyy-MM-dd&#39;T&#39;HH:mm:ss&#39;Z&#39;</value>
        [DataMember(Name = "end_time", EmitDefaultValue = false)]
        public string EndTime { get; set; }

        /// <summary>
        /// isv或商户系统中对应的客服工号
        /// </summary>
        /// <value>isv或商户系统中对应的客服工号</value>
        [DataMember(Name = "external_user_no", EmitDefaultValue = false)]
        public string ExternalUserNo { get; set; }

        /// <summary>
        /// 客服状态变更流水id
        /// </summary>
        /// <value>客服状态变更流水id</value>
        [DataMember(Name = "id", EmitDefaultValue = false)]
        public string Id { get; set; }

        /// <summary>
        /// 变更前状态
        /// </summary>
        /// <value>变更前状态</value>
        [DataMember(Name = "last_status", EmitDefaultValue = false)]
        public string LastStatus { get; set; }

        /// <summary>
        /// 状态变更开始时间,采用UTC时间，按照ISO8601标准表示，格式为：yyyy-MM-dd&#39;T&#39;HH:mm:ss&#39;Z&#39;
        /// </summary>
        /// <value>状态变更开始时间,采用UTC时间，按照ISO8601标准表示，格式为：yyyy-MM-dd&#39;T&#39;HH:mm:ss&#39;Z&#39;</value>
        [DataMember(Name = "start_time", EmitDefaultValue = false)]
        public string StartTime { get; set; }

        /// <summary>
        /// 变更后状态
        /// </summary>
        /// <value>变更后状态</value>
        [DataMember(Name = "status", EmitDefaultValue = false)]
        public string Status { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AgentScheduleLog {\n");
            sb.Append("  AgentId: ").Append(AgentId).Append("\n");
            sb.Append("  AgentName: ").Append(AgentName).Append("\n");
            sb.Append("  CreateTime: ").Append(CreateTime).Append("\n");
            sb.Append("  Duration: ").Append(Duration).Append("\n");
            sb.Append("  EndTime: ").Append(EndTime).Append("\n");
            sb.Append("  ExternalUserNo: ").Append(ExternalUserNo).Append("\n");
            sb.Append("  Id: ").Append(Id).Append("\n");
            sb.Append("  LastStatus: ").Append(LastStatus).Append("\n");
            sb.Append("  StartTime: ").Append(StartTime).Append("\n");
            sb.Append("  Status: ").Append(Status).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }

        /// <summary>
        /// Returns the JSON string presentation of the object
        /// </summary>
        /// <returns>JSON string presentation of the object</returns>
        public virtual string ToJson()
        {
            return Newtonsoft.Json.JsonConvert.SerializeObject(this, Newtonsoft.Json.Formatting.Indented);
        }

        /// <summary>
        /// Returns true if objects are equal
        /// </summary>
        /// <param name="input">Object to be compared</param>
        /// <returns>Boolean</returns>
        public override bool Equals(object input)
        {
            return this.Equals(input as AgentScheduleLog);
        }

        /// <summary>
        /// Returns true if AgentScheduleLog instances are equal
        /// </summary>
        /// <param name="input">Instance of AgentScheduleLog to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AgentScheduleLog input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.AgentId == input.AgentId ||
                    (this.AgentId != null &&
                    this.AgentId.Equals(input.AgentId))
                ) && 
                (
                    this.AgentName == input.AgentName ||
                    (this.AgentName != null &&
                    this.AgentName.Equals(input.AgentName))
                ) && 
                (
                    this.CreateTime == input.CreateTime ||
                    (this.CreateTime != null &&
                    this.CreateTime.Equals(input.CreateTime))
                ) && 
                (
                    this.Duration == input.Duration ||
                    this.Duration.Equals(input.Duration)
                ) && 
                (
                    this.EndTime == input.EndTime ||
                    (this.EndTime != null &&
                    this.EndTime.Equals(input.EndTime))
                ) && 
                (
                    this.ExternalUserNo == input.ExternalUserNo ||
                    (this.ExternalUserNo != null &&
                    this.ExternalUserNo.Equals(input.ExternalUserNo))
                ) && 
                (
                    this.Id == input.Id ||
                    (this.Id != null &&
                    this.Id.Equals(input.Id))
                ) && 
                (
                    this.LastStatus == input.LastStatus ||
                    (this.LastStatus != null &&
                    this.LastStatus.Equals(input.LastStatus))
                ) && 
                (
                    this.StartTime == input.StartTime ||
                    (this.StartTime != null &&
                    this.StartTime.Equals(input.StartTime))
                ) && 
                (
                    this.Status == input.Status ||
                    (this.Status != null &&
                    this.Status.Equals(input.Status))
                );
        }

        /// <summary>
        /// Gets the hash code
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked // Overflow is fine, just wrap
            {
                int hashCode = 41;
                if (this.AgentId != null)
                {
                    hashCode = (hashCode * 59) + this.AgentId.GetHashCode();
                }
                if (this.AgentName != null)
                {
                    hashCode = (hashCode * 59) + this.AgentName.GetHashCode();
                }
                if (this.CreateTime != null)
                {
                    hashCode = (hashCode * 59) + this.CreateTime.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.Duration.GetHashCode();
                if (this.EndTime != null)
                {
                    hashCode = (hashCode * 59) + this.EndTime.GetHashCode();
                }
                if (this.ExternalUserNo != null)
                {
                    hashCode = (hashCode * 59) + this.ExternalUserNo.GetHashCode();
                }
                if (this.Id != null)
                {
                    hashCode = (hashCode * 59) + this.Id.GetHashCode();
                }
                if (this.LastStatus != null)
                {
                    hashCode = (hashCode * 59) + this.LastStatus.GetHashCode();
                }
                if (this.StartTime != null)
                {
                    hashCode = (hashCode * 59) + this.StartTime.GetHashCode();
                }
                if (this.Status != null)
                {
                    hashCode = (hashCode * 59) + this.Status.GetHashCode();
                }
                return hashCode;
            }
        }

        /// <summary>
        /// To validate all properties of the instance
        /// </summary>
        /// <param name="validationContext">Validation context</param>
        /// <returns>Validation Result</returns>
        public IEnumerable<System.ComponentModel.DataAnnotations.ValidationResult> Validate(ValidationContext validationContext)
        {
            yield break;
        }
    }

}
