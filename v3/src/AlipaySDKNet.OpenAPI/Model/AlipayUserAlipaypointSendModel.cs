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
    /// AlipayUserAlipaypointSendModel
    /// </summary>
    [DataContract(Name = "AlipayUserAlipaypointSendModel")]
    public partial class AlipayUserAlipaypointSendModel : IEquatable<AlipayUserAlipaypointSendModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayUserAlipaypointSendModel" /> class.
        /// </summary>
        /// <param name="budgetCode">签约商户的集分宝的预算库，扣除此预算库的集分宝发放给用户。会校验budgetcode和业务方appId的签约商户pid的关联关系，若无关则发放失败。.</param>
        /// <param name="memo">商户关于该笔发放的描述或者信息补充，仅存储，无实际校验功能，该信息会在\&quot;集分宝\&quot;小程序的\&quot;集分宝明细\&quot;中展示给用户。.</param>
        /// <param name="openId">被发放集分宝用户ID，商户app_id维度下的用户标识，与user_account字段二选一。 建议优先使该字段指定发放用户，接口性能更佳.</param>
        /// <param name="partnerBizNo">接入方自己交易的唯一流水ID号，不同交易请保证幂等号唯一性，集分宝服务将依据该字段来进行幂等控制，重试请求不要更换幂等号，需要慎重传递，否则可能会造成损失。.</param>
        /// <param name="pointAmount">发放给用户的集分宝个数。个数区间为 [1,10000000]，需为整数。.</param>
        /// <param name="userAccount">被发放集分宝用户的支付宝登录号，邮箱地址或者手机号均可，与user_id字段二选一，在有user_id时，优先使用user_id字段。.</param>
        /// <param name="userId">被发放集分宝用户的蚂蚁统一会员ID，与user_account字段二选一。 建议优先使用user_id，接口性能更佳，user_id和user_account都传递时，系统优先使用本字段。.</param>
        public AlipayUserAlipaypointSendModel(string budgetCode = default(string), string memo = default(string), string openId = default(string), string partnerBizNo = default(string), int pointAmount = default(int), string userAccount = default(string), string userId = default(string))
        {
            this.BudgetCode = budgetCode;
            this.Memo = memo;
            this.OpenId = openId;
            this.PartnerBizNo = partnerBizNo;
            this.PointAmount = pointAmount;
            this.UserAccount = userAccount;
            this.UserId = userId;
        }

        /// <summary>
        /// 签约商户的集分宝的预算库，扣除此预算库的集分宝发放给用户。会校验budgetcode和业务方appId的签约商户pid的关联关系，若无关则发放失败。
        /// </summary>
        /// <value>签约商户的集分宝的预算库，扣除此预算库的集分宝发放给用户。会校验budgetcode和业务方appId的签约商户pid的关联关系，若无关则发放失败。</value>
        [DataMember(Name = "budget_code", EmitDefaultValue = false)]
        public string BudgetCode { get; set; }

        /// <summary>
        /// 商户关于该笔发放的描述或者信息补充，仅存储，无实际校验功能，该信息会在\&quot;集分宝\&quot;小程序的\&quot;集分宝明细\&quot;中展示给用户。
        /// </summary>
        /// <value>商户关于该笔发放的描述或者信息补充，仅存储，无实际校验功能，该信息会在\&quot;集分宝\&quot;小程序的\&quot;集分宝明细\&quot;中展示给用户。</value>
        [DataMember(Name = "memo", EmitDefaultValue = false)]
        public string Memo { get; set; }

        /// <summary>
        /// 被发放集分宝用户ID，商户app_id维度下的用户标识，与user_account字段二选一。 建议优先使该字段指定发放用户，接口性能更佳
        /// </summary>
        /// <value>被发放集分宝用户ID，商户app_id维度下的用户标识，与user_account字段二选一。 建议优先使该字段指定发放用户，接口性能更佳</value>
        [DataMember(Name = "open_id", EmitDefaultValue = false)]
        public string OpenId { get; set; }

        /// <summary>
        /// 接入方自己交易的唯一流水ID号，不同交易请保证幂等号唯一性，集分宝服务将依据该字段来进行幂等控制，重试请求不要更换幂等号，需要慎重传递，否则可能会造成损失。
        /// </summary>
        /// <value>接入方自己交易的唯一流水ID号，不同交易请保证幂等号唯一性，集分宝服务将依据该字段来进行幂等控制，重试请求不要更换幂等号，需要慎重传递，否则可能会造成损失。</value>
        [DataMember(Name = "partner_biz_no", EmitDefaultValue = false)]
        public string PartnerBizNo { get; set; }

        /// <summary>
        /// 发放给用户的集分宝个数。个数区间为 [1,10000000]，需为整数。
        /// </summary>
        /// <value>发放给用户的集分宝个数。个数区间为 [1,10000000]，需为整数。</value>
        [DataMember(Name = "point_amount", EmitDefaultValue = false)]
        public int PointAmount { get; set; }

        /// <summary>
        /// 被发放集分宝用户的支付宝登录号，邮箱地址或者手机号均可，与user_id字段二选一，在有user_id时，优先使用user_id字段。
        /// </summary>
        /// <value>被发放集分宝用户的支付宝登录号，邮箱地址或者手机号均可，与user_id字段二选一，在有user_id时，优先使用user_id字段。</value>
        [DataMember(Name = "user_account", EmitDefaultValue = false)]
        public string UserAccount { get; set; }

        /// <summary>
        /// 被发放集分宝用户的蚂蚁统一会员ID，与user_account字段二选一。 建议优先使用user_id，接口性能更佳，user_id和user_account都传递时，系统优先使用本字段。
        /// </summary>
        /// <value>被发放集分宝用户的蚂蚁统一会员ID，与user_account字段二选一。 建议优先使用user_id，接口性能更佳，user_id和user_account都传递时，系统优先使用本字段。</value>
        [DataMember(Name = "user_id", EmitDefaultValue = false)]
        public string UserId { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayUserAlipaypointSendModel {\n");
            sb.Append("  BudgetCode: ").Append(BudgetCode).Append("\n");
            sb.Append("  Memo: ").Append(Memo).Append("\n");
            sb.Append("  OpenId: ").Append(OpenId).Append("\n");
            sb.Append("  PartnerBizNo: ").Append(PartnerBizNo).Append("\n");
            sb.Append("  PointAmount: ").Append(PointAmount).Append("\n");
            sb.Append("  UserAccount: ").Append(UserAccount).Append("\n");
            sb.Append("  UserId: ").Append(UserId).Append("\n");
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
            return this.Equals(input as AlipayUserAlipaypointSendModel);
        }

        /// <summary>
        /// Returns true if AlipayUserAlipaypointSendModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayUserAlipaypointSendModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayUserAlipaypointSendModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.BudgetCode == input.BudgetCode ||
                    (this.BudgetCode != null &&
                    this.BudgetCode.Equals(input.BudgetCode))
                ) && 
                (
                    this.Memo == input.Memo ||
                    (this.Memo != null &&
                    this.Memo.Equals(input.Memo))
                ) && 
                (
                    this.OpenId == input.OpenId ||
                    (this.OpenId != null &&
                    this.OpenId.Equals(input.OpenId))
                ) && 
                (
                    this.PartnerBizNo == input.PartnerBizNo ||
                    (this.PartnerBizNo != null &&
                    this.PartnerBizNo.Equals(input.PartnerBizNo))
                ) && 
                (
                    this.PointAmount == input.PointAmount ||
                    this.PointAmount.Equals(input.PointAmount)
                ) && 
                (
                    this.UserAccount == input.UserAccount ||
                    (this.UserAccount != null &&
                    this.UserAccount.Equals(input.UserAccount))
                ) && 
                (
                    this.UserId == input.UserId ||
                    (this.UserId != null &&
                    this.UserId.Equals(input.UserId))
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
                if (this.BudgetCode != null)
                {
                    hashCode = (hashCode * 59) + this.BudgetCode.GetHashCode();
                }
                if (this.Memo != null)
                {
                    hashCode = (hashCode * 59) + this.Memo.GetHashCode();
                }
                if (this.OpenId != null)
                {
                    hashCode = (hashCode * 59) + this.OpenId.GetHashCode();
                }
                if (this.PartnerBizNo != null)
                {
                    hashCode = (hashCode * 59) + this.PartnerBizNo.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.PointAmount.GetHashCode();
                if (this.UserAccount != null)
                {
                    hashCode = (hashCode * 59) + this.UserAccount.GetHashCode();
                }
                if (this.UserId != null)
                {
                    hashCode = (hashCode * 59) + this.UserId.GetHashCode();
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
