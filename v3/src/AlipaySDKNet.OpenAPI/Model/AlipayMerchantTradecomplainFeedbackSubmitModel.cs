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
    /// AlipayMerchantTradecomplainFeedbackSubmitModel
    /// </summary>
    [DataContract(Name = "AlipayMerchantTradecomplainFeedbackSubmitModel")]
    public partial class AlipayMerchantTradecomplainFeedbackSubmitModel : IEquatable<AlipayMerchantTradecomplainFeedbackSubmitModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayMerchantTradecomplainFeedbackSubmitModel" /> class.
        /// </summary>
        /// <param name="complainEventId">支付宝侧投诉单号.</param>
        /// <param name="feedbackCode">反馈类目ID 00:使用体验保障金退款； 02:通过其他方式退款; 03:已发货; 04:其他; 05:已完成售后服务; 06:非我方责任范围；.</param>
        /// <param name="feedbackContent">反馈内容，字数不超过200个字.</param>
        /// <param name="feedbackImages">商家处理投诉时反馈凭证的图片id，多个逗号隔开（图片id可以通过\&quot;商户上传处理图片\&quot;接口获取）.</param>
        /// <param name="_operator">处理投诉人，字数不超过6个字.</param>
        public AlipayMerchantTradecomplainFeedbackSubmitModel(string complainEventId = default(string), string feedbackCode = default(string), string feedbackContent = default(string), string feedbackImages = default(string), string _operator = default(string))
        {
            this.ComplainEventId = complainEventId;
            this.FeedbackCode = feedbackCode;
            this.FeedbackContent = feedbackContent;
            this.FeedbackImages = feedbackImages;
            this.Operator = _operator;
        }

        /// <summary>
        /// 支付宝侧投诉单号
        /// </summary>
        /// <value>支付宝侧投诉单号</value>
        [DataMember(Name = "complain_event_id", EmitDefaultValue = false)]
        public string ComplainEventId { get; set; }

        /// <summary>
        /// 反馈类目ID 00:使用体验保障金退款； 02:通过其他方式退款; 03:已发货; 04:其他; 05:已完成售后服务; 06:非我方责任范围；
        /// </summary>
        /// <value>反馈类目ID 00:使用体验保障金退款； 02:通过其他方式退款; 03:已发货; 04:其他; 05:已完成售后服务; 06:非我方责任范围；</value>
        [DataMember(Name = "feedback_code", EmitDefaultValue = false)]
        public string FeedbackCode { get; set; }

        /// <summary>
        /// 反馈内容，字数不超过200个字
        /// </summary>
        /// <value>反馈内容，字数不超过200个字</value>
        [DataMember(Name = "feedback_content", EmitDefaultValue = false)]
        public string FeedbackContent { get; set; }

        /// <summary>
        /// 商家处理投诉时反馈凭证的图片id，多个逗号隔开（图片id可以通过\&quot;商户上传处理图片\&quot;接口获取）
        /// </summary>
        /// <value>商家处理投诉时反馈凭证的图片id，多个逗号隔开（图片id可以通过\&quot;商户上传处理图片\&quot;接口获取）</value>
        [DataMember(Name = "feedback_images", EmitDefaultValue = false)]
        public string FeedbackImages { get; set; }

        /// <summary>
        /// 处理投诉人，字数不超过6个字
        /// </summary>
        /// <value>处理投诉人，字数不超过6个字</value>
        [DataMember(Name = "operator", EmitDefaultValue = false)]
        public string Operator { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayMerchantTradecomplainFeedbackSubmitModel {\n");
            sb.Append("  ComplainEventId: ").Append(ComplainEventId).Append("\n");
            sb.Append("  FeedbackCode: ").Append(FeedbackCode).Append("\n");
            sb.Append("  FeedbackContent: ").Append(FeedbackContent).Append("\n");
            sb.Append("  FeedbackImages: ").Append(FeedbackImages).Append("\n");
            sb.Append("  Operator: ").Append(Operator).Append("\n");
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
            return this.Equals(input as AlipayMerchantTradecomplainFeedbackSubmitModel);
        }

        /// <summary>
        /// Returns true if AlipayMerchantTradecomplainFeedbackSubmitModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayMerchantTradecomplainFeedbackSubmitModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayMerchantTradecomplainFeedbackSubmitModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.ComplainEventId == input.ComplainEventId ||
                    (this.ComplainEventId != null &&
                    this.ComplainEventId.Equals(input.ComplainEventId))
                ) && 
                (
                    this.FeedbackCode == input.FeedbackCode ||
                    (this.FeedbackCode != null &&
                    this.FeedbackCode.Equals(input.FeedbackCode))
                ) && 
                (
                    this.FeedbackContent == input.FeedbackContent ||
                    (this.FeedbackContent != null &&
                    this.FeedbackContent.Equals(input.FeedbackContent))
                ) && 
                (
                    this.FeedbackImages == input.FeedbackImages ||
                    (this.FeedbackImages != null &&
                    this.FeedbackImages.Equals(input.FeedbackImages))
                ) && 
                (
                    this.Operator == input.Operator ||
                    (this.Operator != null &&
                    this.Operator.Equals(input.Operator))
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
                if (this.ComplainEventId != null)
                {
                    hashCode = (hashCode * 59) + this.ComplainEventId.GetHashCode();
                }
                if (this.FeedbackCode != null)
                {
                    hashCode = (hashCode * 59) + this.FeedbackCode.GetHashCode();
                }
                if (this.FeedbackContent != null)
                {
                    hashCode = (hashCode * 59) + this.FeedbackContent.GetHashCode();
                }
                if (this.FeedbackImages != null)
                {
                    hashCode = (hashCode * 59) + this.FeedbackImages.GetHashCode();
                }
                if (this.Operator != null)
                {
                    hashCode = (hashCode * 59) + this.Operator.GetHashCode();
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
