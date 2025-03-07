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
    /// AlipayOpenSearchBoxactivityQueryResponseModel
    /// </summary>
    [DataContract(Name = "AlipayOpenSearchBoxactivityQueryResponseModel")]
    public partial class AlipayOpenSearchBoxactivityQueryResponseModel : IEquatable<AlipayOpenSearchBoxactivityQueryResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenSearchBoxactivityQueryResponseModel" /> class.
        /// </summary>
        /// <param name="backgroundWord">底纹词.</param>
        /// <param name="backgroundWordInfo">backgroundWordInfo.</param>
        /// <param name="boxActivityId">搜索直达活动id.</param>
        /// <param name="boxId">搜索直达id.</param>
        /// <param name="endTime">活动结束时间.</param>
        /// <param name="failReason">审核失败原因.</param>
        /// <param name="gmtModified">更新时间.</param>
        /// <param name="materialType">IMAGE-图片/VIDEO-视频.</param>
        /// <param name="materialUrl">当material_type&#x3D;\&quot;IMAGE\&quot;时，为图片url；当material_type&#x3D;\&quot;VIDEO\&quot;时，为视频url.</param>
        /// <param name="orientedRule">orientedRule.</param>
        /// <param name="runStatus">运行状态，INITIAL-初始/ONLINE-已上架/EXPIRE-已失效/OFFLINE-已下架.</param>
        /// <param name="startTime">活动开始时间.</param>
        /// <param name="status">配置状态，INITIAL-初始/AUDIT-审核中/CANCEL-已取消/ONLINE-已上架/REJECT-驳回/OFFLINE-已下架/EXPIRE-已失效.</param>
        /// <param name="targetAppid">跳转应用ID.</param>
        /// <param name="targetAppname">模板名称.</param>
        /// <param name="targetRegions">投放目标区域.</param>
        /// <param name="title">活动标题.</param>
        /// <param name="videoInfo">videoInfo.</param>
        public AlipayOpenSearchBoxactivityQueryResponseModel(string backgroundWord = default(string), BackgroundWordInfo backgroundWordInfo = default(BackgroundWordInfo), string boxActivityId = default(string), string boxId = default(string), string endTime = default(string), string failReason = default(string), string gmtModified = default(string), string materialType = default(string), string materialUrl = default(string), DeliveryOrientedRuleInfo orientedRule = default(DeliveryOrientedRuleInfo), string runStatus = default(string), string startTime = default(string), string status = default(string), string targetAppid = default(string), string targetAppname = default(string), List<DeliveryTargetRegion> targetRegions = default(List<DeliveryTargetRegion>), string title = default(string), SearchBoxActivityVideoInfo videoInfo = default(SearchBoxActivityVideoInfo))
        {
            this.BackgroundWord = backgroundWord;
            this.BackgroundWordInfo = backgroundWordInfo;
            this.BoxActivityId = boxActivityId;
            this.BoxId = boxId;
            this.EndTime = endTime;
            this.FailReason = failReason;
            this.GmtModified = gmtModified;
            this.MaterialType = materialType;
            this.MaterialUrl = materialUrl;
            this.OrientedRule = orientedRule;
            this.RunStatus = runStatus;
            this.StartTime = startTime;
            this.Status = status;
            this.TargetAppid = targetAppid;
            this.TargetAppname = targetAppname;
            this.TargetRegions = targetRegions;
            this.Title = title;
            this.VideoInfo = videoInfo;
        }

        /// <summary>
        /// 底纹词
        /// </summary>
        /// <value>底纹词</value>
        [DataMember(Name = "background_word", EmitDefaultValue = false)]
        public string BackgroundWord { get; set; }

        /// <summary>
        /// Gets or Sets BackgroundWordInfo
        /// </summary>
        [DataMember(Name = "background_word_info", EmitDefaultValue = false)]
        public BackgroundWordInfo BackgroundWordInfo { get; set; }

        /// <summary>
        /// 搜索直达活动id
        /// </summary>
        /// <value>搜索直达活动id</value>
        [DataMember(Name = "box_activity_id", EmitDefaultValue = false)]
        public string BoxActivityId { get; set; }

        /// <summary>
        /// 搜索直达id
        /// </summary>
        /// <value>搜索直达id</value>
        [DataMember(Name = "box_id", EmitDefaultValue = false)]
        public string BoxId { get; set; }

        /// <summary>
        /// 活动结束时间
        /// </summary>
        /// <value>活动结束时间</value>
        [DataMember(Name = "end_time", EmitDefaultValue = false)]
        public string EndTime { get; set; }

        /// <summary>
        /// 审核失败原因
        /// </summary>
        /// <value>审核失败原因</value>
        [DataMember(Name = "fail_reason", EmitDefaultValue = false)]
        public string FailReason { get; set; }

        /// <summary>
        /// 更新时间
        /// </summary>
        /// <value>更新时间</value>
        [DataMember(Name = "gmt_modified", EmitDefaultValue = false)]
        public string GmtModified { get; set; }

        /// <summary>
        /// IMAGE-图片/VIDEO-视频
        /// </summary>
        /// <value>IMAGE-图片/VIDEO-视频</value>
        [DataMember(Name = "material_type", EmitDefaultValue = false)]
        public string MaterialType { get; set; }

        /// <summary>
        /// 当material_type&#x3D;\&quot;IMAGE\&quot;时，为图片url；当material_type&#x3D;\&quot;VIDEO\&quot;时，为视频url
        /// </summary>
        /// <value>当material_type&#x3D;\&quot;IMAGE\&quot;时，为图片url；当material_type&#x3D;\&quot;VIDEO\&quot;时，为视频url</value>
        [DataMember(Name = "material_url", EmitDefaultValue = false)]
        public string MaterialUrl { get; set; }

        /// <summary>
        /// Gets or Sets OrientedRule
        /// </summary>
        [DataMember(Name = "oriented_rule", EmitDefaultValue = false)]
        public DeliveryOrientedRuleInfo OrientedRule { get; set; }

        /// <summary>
        /// 运行状态，INITIAL-初始/ONLINE-已上架/EXPIRE-已失效/OFFLINE-已下架
        /// </summary>
        /// <value>运行状态，INITIAL-初始/ONLINE-已上架/EXPIRE-已失效/OFFLINE-已下架</value>
        [DataMember(Name = "run_status", EmitDefaultValue = false)]
        public string RunStatus { get; set; }

        /// <summary>
        /// 活动开始时间
        /// </summary>
        /// <value>活动开始时间</value>
        [DataMember(Name = "start_time", EmitDefaultValue = false)]
        public string StartTime { get; set; }

        /// <summary>
        /// 配置状态，INITIAL-初始/AUDIT-审核中/CANCEL-已取消/ONLINE-已上架/REJECT-驳回/OFFLINE-已下架/EXPIRE-已失效
        /// </summary>
        /// <value>配置状态，INITIAL-初始/AUDIT-审核中/CANCEL-已取消/ONLINE-已上架/REJECT-驳回/OFFLINE-已下架/EXPIRE-已失效</value>
        [DataMember(Name = "status", EmitDefaultValue = false)]
        public string Status { get; set; }

        /// <summary>
        /// 跳转应用ID
        /// </summary>
        /// <value>跳转应用ID</value>
        [DataMember(Name = "target_appid", EmitDefaultValue = false)]
        public string TargetAppid { get; set; }

        /// <summary>
        /// 模板名称
        /// </summary>
        /// <value>模板名称</value>
        [DataMember(Name = "target_appname", EmitDefaultValue = false)]
        public string TargetAppname { get; set; }

        /// <summary>
        /// 投放目标区域
        /// </summary>
        /// <value>投放目标区域</value>
        [DataMember(Name = "target_regions", EmitDefaultValue = false)]
        public List<DeliveryTargetRegion> TargetRegions { get; set; }

        /// <summary>
        /// 活动标题
        /// </summary>
        /// <value>活动标题</value>
        [DataMember(Name = "title", EmitDefaultValue = false)]
        public string Title { get; set; }

        /// <summary>
        /// Gets or Sets VideoInfo
        /// </summary>
        [DataMember(Name = "video_info", EmitDefaultValue = false)]
        public SearchBoxActivityVideoInfo VideoInfo { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOpenSearchBoxactivityQueryResponseModel {\n");
            sb.Append("  BackgroundWord: ").Append(BackgroundWord).Append("\n");
            sb.Append("  BackgroundWordInfo: ").Append(BackgroundWordInfo).Append("\n");
            sb.Append("  BoxActivityId: ").Append(BoxActivityId).Append("\n");
            sb.Append("  BoxId: ").Append(BoxId).Append("\n");
            sb.Append("  EndTime: ").Append(EndTime).Append("\n");
            sb.Append("  FailReason: ").Append(FailReason).Append("\n");
            sb.Append("  GmtModified: ").Append(GmtModified).Append("\n");
            sb.Append("  MaterialType: ").Append(MaterialType).Append("\n");
            sb.Append("  MaterialUrl: ").Append(MaterialUrl).Append("\n");
            sb.Append("  OrientedRule: ").Append(OrientedRule).Append("\n");
            sb.Append("  RunStatus: ").Append(RunStatus).Append("\n");
            sb.Append("  StartTime: ").Append(StartTime).Append("\n");
            sb.Append("  Status: ").Append(Status).Append("\n");
            sb.Append("  TargetAppid: ").Append(TargetAppid).Append("\n");
            sb.Append("  TargetAppname: ").Append(TargetAppname).Append("\n");
            sb.Append("  TargetRegions: ").Append(TargetRegions).Append("\n");
            sb.Append("  Title: ").Append(Title).Append("\n");
            sb.Append("  VideoInfo: ").Append(VideoInfo).Append("\n");
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
            return this.Equals(input as AlipayOpenSearchBoxactivityQueryResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenSearchBoxactivityQueryResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenSearchBoxactivityQueryResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenSearchBoxactivityQueryResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.BackgroundWord == input.BackgroundWord ||
                    (this.BackgroundWord != null &&
                    this.BackgroundWord.Equals(input.BackgroundWord))
                ) && 
                (
                    this.BackgroundWordInfo == input.BackgroundWordInfo ||
                    (this.BackgroundWordInfo != null &&
                    this.BackgroundWordInfo.Equals(input.BackgroundWordInfo))
                ) && 
                (
                    this.BoxActivityId == input.BoxActivityId ||
                    (this.BoxActivityId != null &&
                    this.BoxActivityId.Equals(input.BoxActivityId))
                ) && 
                (
                    this.BoxId == input.BoxId ||
                    (this.BoxId != null &&
                    this.BoxId.Equals(input.BoxId))
                ) && 
                (
                    this.EndTime == input.EndTime ||
                    (this.EndTime != null &&
                    this.EndTime.Equals(input.EndTime))
                ) && 
                (
                    this.FailReason == input.FailReason ||
                    (this.FailReason != null &&
                    this.FailReason.Equals(input.FailReason))
                ) && 
                (
                    this.GmtModified == input.GmtModified ||
                    (this.GmtModified != null &&
                    this.GmtModified.Equals(input.GmtModified))
                ) && 
                (
                    this.MaterialType == input.MaterialType ||
                    (this.MaterialType != null &&
                    this.MaterialType.Equals(input.MaterialType))
                ) && 
                (
                    this.MaterialUrl == input.MaterialUrl ||
                    (this.MaterialUrl != null &&
                    this.MaterialUrl.Equals(input.MaterialUrl))
                ) && 
                (
                    this.OrientedRule == input.OrientedRule ||
                    (this.OrientedRule != null &&
                    this.OrientedRule.Equals(input.OrientedRule))
                ) && 
                (
                    this.RunStatus == input.RunStatus ||
                    (this.RunStatus != null &&
                    this.RunStatus.Equals(input.RunStatus))
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
                ) && 
                (
                    this.TargetAppid == input.TargetAppid ||
                    (this.TargetAppid != null &&
                    this.TargetAppid.Equals(input.TargetAppid))
                ) && 
                (
                    this.TargetAppname == input.TargetAppname ||
                    (this.TargetAppname != null &&
                    this.TargetAppname.Equals(input.TargetAppname))
                ) && 
                (
                    this.TargetRegions == input.TargetRegions ||
                    this.TargetRegions != null &&
                    input.TargetRegions != null &&
                    this.TargetRegions.SequenceEqual(input.TargetRegions)
                ) && 
                (
                    this.Title == input.Title ||
                    (this.Title != null &&
                    this.Title.Equals(input.Title))
                ) && 
                (
                    this.VideoInfo == input.VideoInfo ||
                    (this.VideoInfo != null &&
                    this.VideoInfo.Equals(input.VideoInfo))
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
                if (this.BackgroundWord != null)
                {
                    hashCode = (hashCode * 59) + this.BackgroundWord.GetHashCode();
                }
                if (this.BackgroundWordInfo != null)
                {
                    hashCode = (hashCode * 59) + this.BackgroundWordInfo.GetHashCode();
                }
                if (this.BoxActivityId != null)
                {
                    hashCode = (hashCode * 59) + this.BoxActivityId.GetHashCode();
                }
                if (this.BoxId != null)
                {
                    hashCode = (hashCode * 59) + this.BoxId.GetHashCode();
                }
                if (this.EndTime != null)
                {
                    hashCode = (hashCode * 59) + this.EndTime.GetHashCode();
                }
                if (this.FailReason != null)
                {
                    hashCode = (hashCode * 59) + this.FailReason.GetHashCode();
                }
                if (this.GmtModified != null)
                {
                    hashCode = (hashCode * 59) + this.GmtModified.GetHashCode();
                }
                if (this.MaterialType != null)
                {
                    hashCode = (hashCode * 59) + this.MaterialType.GetHashCode();
                }
                if (this.MaterialUrl != null)
                {
                    hashCode = (hashCode * 59) + this.MaterialUrl.GetHashCode();
                }
                if (this.OrientedRule != null)
                {
                    hashCode = (hashCode * 59) + this.OrientedRule.GetHashCode();
                }
                if (this.RunStatus != null)
                {
                    hashCode = (hashCode * 59) + this.RunStatus.GetHashCode();
                }
                if (this.StartTime != null)
                {
                    hashCode = (hashCode * 59) + this.StartTime.GetHashCode();
                }
                if (this.Status != null)
                {
                    hashCode = (hashCode * 59) + this.Status.GetHashCode();
                }
                if (this.TargetAppid != null)
                {
                    hashCode = (hashCode * 59) + this.TargetAppid.GetHashCode();
                }
                if (this.TargetAppname != null)
                {
                    hashCode = (hashCode * 59) + this.TargetAppname.GetHashCode();
                }
                if (this.TargetRegions != null)
                {
                    hashCode = (hashCode * 59) + this.TargetRegions.GetHashCode();
                }
                if (this.Title != null)
                {
                    hashCode = (hashCode * 59) + this.Title.GetHashCode();
                }
                if (this.VideoInfo != null)
                {
                    hashCode = (hashCode * 59) + this.VideoInfo.GetHashCode();
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
