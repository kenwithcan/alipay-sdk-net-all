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
    /// AlipayOpenPublicMessageContentModifyModel
    /// </summary>
    [DataContract(Name = "AlipayOpenPublicMessageContentModifyModel")]
    public partial class AlipayOpenPublicMessageContentModifyModel : IEquatable<AlipayOpenPublicMessageContentModifyModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenPublicMessageContentModifyModel" /> class.
        /// </summary>
        /// <param name="benefit">活动利益点，图文类型ctype为activity类型时才需要传，最多10个字符.</param>
        /// <param name="content">消息正文（支持富文本）.</param>
        /// <param name="contentId">内容id.</param>
        /// <param name="couldComment">是否允许评论 T:允许 F:不允许，默认不允许.</param>
        /// <param name="cover">封面图url, 尺寸为996*450，最大不超过3M，支持格式:.jpg、.png ，请先调用&lt;ahref&#x3D;\&quot;https://docs.open.alipay.com/api_3/alipay.offline.material.image.upload\&quot;&gt; 图片上传接口&lt;/a&gt;获得图片url。.</param>
        /// <param name="ctype">图文类型  activity: 活动图文，不填默认普通图文.</param>
        /// <param name="extTags">关键词列表，英文逗号分隔，最多不超过5个.</param>
        /// <param name="loginIds">可预览支付宝账号列表，需要预览时才填写， 英文逗号分隔，最多不超过10个.</param>
        /// <param name="title">标题.</param>
        public AlipayOpenPublicMessageContentModifyModel(string benefit = default(string), string content = default(string), string contentId = default(string), string couldComment = default(string), string cover = default(string), string ctype = default(string), string extTags = default(string), string loginIds = default(string), string title = default(string))
        {
            this.Benefit = benefit;
            this.Content = content;
            this.ContentId = contentId;
            this.CouldComment = couldComment;
            this.Cover = cover;
            this.Ctype = ctype;
            this.ExtTags = extTags;
            this.LoginIds = loginIds;
            this.Title = title;
        }

        /// <summary>
        /// 活动利益点，图文类型ctype为activity类型时才需要传，最多10个字符
        /// </summary>
        /// <value>活动利益点，图文类型ctype为activity类型时才需要传，最多10个字符</value>
        [DataMember(Name = "benefit", EmitDefaultValue = false)]
        public string Benefit { get; set; }

        /// <summary>
        /// 消息正文（支持富文本）
        /// </summary>
        /// <value>消息正文（支持富文本）</value>
        [DataMember(Name = "content", EmitDefaultValue = false)]
        public string Content { get; set; }

        /// <summary>
        /// 内容id
        /// </summary>
        /// <value>内容id</value>
        [DataMember(Name = "content_id", EmitDefaultValue = false)]
        public string ContentId { get; set; }

        /// <summary>
        /// 是否允许评论 T:允许 F:不允许，默认不允许
        /// </summary>
        /// <value>是否允许评论 T:允许 F:不允许，默认不允许</value>
        [DataMember(Name = "could_comment", EmitDefaultValue = false)]
        public string CouldComment { get; set; }

        /// <summary>
        /// 封面图url, 尺寸为996*450，最大不超过3M，支持格式:.jpg、.png ，请先调用&lt;ahref&#x3D;\&quot;https://docs.open.alipay.com/api_3/alipay.offline.material.image.upload\&quot;&gt; 图片上传接口&lt;/a&gt;获得图片url。
        /// </summary>
        /// <value>封面图url, 尺寸为996*450，最大不超过3M，支持格式:.jpg、.png ，请先调用&lt;ahref&#x3D;\&quot;https://docs.open.alipay.com/api_3/alipay.offline.material.image.upload\&quot;&gt; 图片上传接口&lt;/a&gt;获得图片url。</value>
        [DataMember(Name = "cover", EmitDefaultValue = false)]
        public string Cover { get; set; }

        /// <summary>
        /// 图文类型  activity: 活动图文，不填默认普通图文
        /// </summary>
        /// <value>图文类型  activity: 活动图文，不填默认普通图文</value>
        [DataMember(Name = "ctype", EmitDefaultValue = false)]
        public string Ctype { get; set; }

        /// <summary>
        /// 关键词列表，英文逗号分隔，最多不超过5个
        /// </summary>
        /// <value>关键词列表，英文逗号分隔，最多不超过5个</value>
        [DataMember(Name = "ext_tags", EmitDefaultValue = false)]
        public string ExtTags { get; set; }

        /// <summary>
        /// 可预览支付宝账号列表，需要预览时才填写， 英文逗号分隔，最多不超过10个
        /// </summary>
        /// <value>可预览支付宝账号列表，需要预览时才填写， 英文逗号分隔，最多不超过10个</value>
        [DataMember(Name = "login_ids", EmitDefaultValue = false)]
        public string LoginIds { get; set; }

        /// <summary>
        /// 标题
        /// </summary>
        /// <value>标题</value>
        [DataMember(Name = "title", EmitDefaultValue = false)]
        public string Title { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOpenPublicMessageContentModifyModel {\n");
            sb.Append("  Benefit: ").Append(Benefit).Append("\n");
            sb.Append("  Content: ").Append(Content).Append("\n");
            sb.Append("  ContentId: ").Append(ContentId).Append("\n");
            sb.Append("  CouldComment: ").Append(CouldComment).Append("\n");
            sb.Append("  Cover: ").Append(Cover).Append("\n");
            sb.Append("  Ctype: ").Append(Ctype).Append("\n");
            sb.Append("  ExtTags: ").Append(ExtTags).Append("\n");
            sb.Append("  LoginIds: ").Append(LoginIds).Append("\n");
            sb.Append("  Title: ").Append(Title).Append("\n");
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
            return this.Equals(input as AlipayOpenPublicMessageContentModifyModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenPublicMessageContentModifyModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenPublicMessageContentModifyModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenPublicMessageContentModifyModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Benefit == input.Benefit ||
                    (this.Benefit != null &&
                    this.Benefit.Equals(input.Benefit))
                ) && 
                (
                    this.Content == input.Content ||
                    (this.Content != null &&
                    this.Content.Equals(input.Content))
                ) && 
                (
                    this.ContentId == input.ContentId ||
                    (this.ContentId != null &&
                    this.ContentId.Equals(input.ContentId))
                ) && 
                (
                    this.CouldComment == input.CouldComment ||
                    (this.CouldComment != null &&
                    this.CouldComment.Equals(input.CouldComment))
                ) && 
                (
                    this.Cover == input.Cover ||
                    (this.Cover != null &&
                    this.Cover.Equals(input.Cover))
                ) && 
                (
                    this.Ctype == input.Ctype ||
                    (this.Ctype != null &&
                    this.Ctype.Equals(input.Ctype))
                ) && 
                (
                    this.ExtTags == input.ExtTags ||
                    (this.ExtTags != null &&
                    this.ExtTags.Equals(input.ExtTags))
                ) && 
                (
                    this.LoginIds == input.LoginIds ||
                    (this.LoginIds != null &&
                    this.LoginIds.Equals(input.LoginIds))
                ) && 
                (
                    this.Title == input.Title ||
                    (this.Title != null &&
                    this.Title.Equals(input.Title))
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
                if (this.Benefit != null)
                {
                    hashCode = (hashCode * 59) + this.Benefit.GetHashCode();
                }
                if (this.Content != null)
                {
                    hashCode = (hashCode * 59) + this.Content.GetHashCode();
                }
                if (this.ContentId != null)
                {
                    hashCode = (hashCode * 59) + this.ContentId.GetHashCode();
                }
                if (this.CouldComment != null)
                {
                    hashCode = (hashCode * 59) + this.CouldComment.GetHashCode();
                }
                if (this.Cover != null)
                {
                    hashCode = (hashCode * 59) + this.Cover.GetHashCode();
                }
                if (this.Ctype != null)
                {
                    hashCode = (hashCode * 59) + this.Ctype.GetHashCode();
                }
                if (this.ExtTags != null)
                {
                    hashCode = (hashCode * 59) + this.ExtTags.GetHashCode();
                }
                if (this.LoginIds != null)
                {
                    hashCode = (hashCode * 59) + this.LoginIds.GetHashCode();
                }
                if (this.Title != null)
                {
                    hashCode = (hashCode * 59) + this.Title.GetHashCode();
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
