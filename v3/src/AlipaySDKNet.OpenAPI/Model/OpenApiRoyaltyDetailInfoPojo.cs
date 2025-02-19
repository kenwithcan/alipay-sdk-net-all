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
    /// OpenApiRoyaltyDetailInfoPojo
    /// </summary>
    [DataContract(Name = "OpenApiRoyaltyDetailInfoPojo")]
    public partial class OpenApiRoyaltyDetailInfoPojo : IEquatable<OpenApiRoyaltyDetailInfoPojo>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenApiRoyaltyDetailInfoPojo" /> class.
        /// </summary>
        /// <param name="amount">分账的金额，单位为元.</param>
        /// <param name="amountPercentage">分账信息中分账百分比。取值范围为大于0，少于或等于100的整数。.</param>
        /// <param name="desc">分账描述.</param>
        /// <param name="royaltyScene">可选值：达人佣金、平台服务费、技术服务费、其他.</param>
        /// <param name="royaltyType">分账类型..</param>
        /// <param name="transIn">收入方账户。如果收入方账户类型为userId，本参数为收入方的支付宝账号对应的支付宝唯一用户号，以2088开头的纯16位数字；如果收入方类型为cardAliasNo，本参数为收入方在支付宝绑定的卡编号；如果收入方类型为loginName，本参数为收入方的支付宝登录号；.</param>
        /// <param name="transInName">分账收款方姓名，上送则进行姓名与支付宝账号的一致性校验，校验不一致则分账失败。不上送则不进行姓名校验.</param>
        /// <param name="transInType">收入方账户类型。.</param>
        /// <param name="transOut">支出方账户。如果支出方账户类型为userId，本参数为支出方的支付宝账号对应的支付宝唯一用户号，以2088开头的纯16位数字；如果支出方类型为loginName，本参数为支出方的支付宝登录号。 泛金融类商户分账时，该字段不要上送。.</param>
        /// <param name="transOutType">支出方账户类型。.</param>
        public OpenApiRoyaltyDetailInfoPojo(string amount = default(string), int amountPercentage = default(int), string desc = default(string), string royaltyScene = default(string), string royaltyType = default(string), string transIn = default(string), string transInName = default(string), string transInType = default(string), string transOut = default(string), string transOutType = default(string))
        {
            this.Amount = amount;
            this.AmountPercentage = amountPercentage;
            this.Desc = desc;
            this.RoyaltyScene = royaltyScene;
            this.RoyaltyType = royaltyType;
            this.TransIn = transIn;
            this.TransInName = transInName;
            this.TransInType = transInType;
            this.TransOut = transOut;
            this.TransOutType = transOutType;
        }

        /// <summary>
        /// 分账的金额，单位为元
        /// </summary>
        /// <value>分账的金额，单位为元</value>
        [DataMember(Name = "amount", EmitDefaultValue = false)]
        public string Amount { get; set; }

        /// <summary>
        /// 分账信息中分账百分比。取值范围为大于0，少于或等于100的整数。
        /// </summary>
        /// <value>分账信息中分账百分比。取值范围为大于0，少于或等于100的整数。</value>
        [DataMember(Name = "amount_percentage", EmitDefaultValue = false)]
        public int AmountPercentage { get; set; }

        /// <summary>
        /// 分账描述
        /// </summary>
        /// <value>分账描述</value>
        [DataMember(Name = "desc", EmitDefaultValue = false)]
        public string Desc { get; set; }

        /// <summary>
        /// 可选值：达人佣金、平台服务费、技术服务费、其他
        /// </summary>
        /// <value>可选值：达人佣金、平台服务费、技术服务费、其他</value>
        [DataMember(Name = "royalty_scene", EmitDefaultValue = false)]
        public string RoyaltyScene { get; set; }

        /// <summary>
        /// 分账类型.
        /// </summary>
        /// <value>分账类型.</value>
        [DataMember(Name = "royalty_type", EmitDefaultValue = false)]
        public string RoyaltyType { get; set; }

        /// <summary>
        /// 收入方账户。如果收入方账户类型为userId，本参数为收入方的支付宝账号对应的支付宝唯一用户号，以2088开头的纯16位数字；如果收入方类型为cardAliasNo，本参数为收入方在支付宝绑定的卡编号；如果收入方类型为loginName，本参数为收入方的支付宝登录号；
        /// </summary>
        /// <value>收入方账户。如果收入方账户类型为userId，本参数为收入方的支付宝账号对应的支付宝唯一用户号，以2088开头的纯16位数字；如果收入方类型为cardAliasNo，本参数为收入方在支付宝绑定的卡编号；如果收入方类型为loginName，本参数为收入方的支付宝登录号；</value>
        [DataMember(Name = "trans_in", EmitDefaultValue = false)]
        public string TransIn { get; set; }

        /// <summary>
        /// 分账收款方姓名，上送则进行姓名与支付宝账号的一致性校验，校验不一致则分账失败。不上送则不进行姓名校验
        /// </summary>
        /// <value>分账收款方姓名，上送则进行姓名与支付宝账号的一致性校验，校验不一致则分账失败。不上送则不进行姓名校验</value>
        [DataMember(Name = "trans_in_name", EmitDefaultValue = false)]
        public string TransInName { get; set; }

        /// <summary>
        /// 收入方账户类型。
        /// </summary>
        /// <value>收入方账户类型。</value>
        [DataMember(Name = "trans_in_type", EmitDefaultValue = false)]
        public string TransInType { get; set; }

        /// <summary>
        /// 支出方账户。如果支出方账户类型为userId，本参数为支出方的支付宝账号对应的支付宝唯一用户号，以2088开头的纯16位数字；如果支出方类型为loginName，本参数为支出方的支付宝登录号。 泛金融类商户分账时，该字段不要上送。
        /// </summary>
        /// <value>支出方账户。如果支出方账户类型为userId，本参数为支出方的支付宝账号对应的支付宝唯一用户号，以2088开头的纯16位数字；如果支出方类型为loginName，本参数为支出方的支付宝登录号。 泛金融类商户分账时，该字段不要上送。</value>
        [DataMember(Name = "trans_out", EmitDefaultValue = false)]
        public string TransOut { get; set; }

        /// <summary>
        /// 支出方账户类型。
        /// </summary>
        /// <value>支出方账户类型。</value>
        [DataMember(Name = "trans_out_type", EmitDefaultValue = false)]
        public string TransOutType { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class OpenApiRoyaltyDetailInfoPojo {\n");
            sb.Append("  Amount: ").Append(Amount).Append("\n");
            sb.Append("  AmountPercentage: ").Append(AmountPercentage).Append("\n");
            sb.Append("  Desc: ").Append(Desc).Append("\n");
            sb.Append("  RoyaltyScene: ").Append(RoyaltyScene).Append("\n");
            sb.Append("  RoyaltyType: ").Append(RoyaltyType).Append("\n");
            sb.Append("  TransIn: ").Append(TransIn).Append("\n");
            sb.Append("  TransInName: ").Append(TransInName).Append("\n");
            sb.Append("  TransInType: ").Append(TransInType).Append("\n");
            sb.Append("  TransOut: ").Append(TransOut).Append("\n");
            sb.Append("  TransOutType: ").Append(TransOutType).Append("\n");
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
            return this.Equals(input as OpenApiRoyaltyDetailInfoPojo);
        }

        /// <summary>
        /// Returns true if OpenApiRoyaltyDetailInfoPojo instances are equal
        /// </summary>
        /// <param name="input">Instance of OpenApiRoyaltyDetailInfoPojo to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(OpenApiRoyaltyDetailInfoPojo input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Amount == input.Amount ||
                    (this.Amount != null &&
                    this.Amount.Equals(input.Amount))
                ) && 
                (
                    this.AmountPercentage == input.AmountPercentage ||
                    this.AmountPercentage.Equals(input.AmountPercentage)
                ) && 
                (
                    this.Desc == input.Desc ||
                    (this.Desc != null &&
                    this.Desc.Equals(input.Desc))
                ) && 
                (
                    this.RoyaltyScene == input.RoyaltyScene ||
                    (this.RoyaltyScene != null &&
                    this.RoyaltyScene.Equals(input.RoyaltyScene))
                ) && 
                (
                    this.RoyaltyType == input.RoyaltyType ||
                    (this.RoyaltyType != null &&
                    this.RoyaltyType.Equals(input.RoyaltyType))
                ) && 
                (
                    this.TransIn == input.TransIn ||
                    (this.TransIn != null &&
                    this.TransIn.Equals(input.TransIn))
                ) && 
                (
                    this.TransInName == input.TransInName ||
                    (this.TransInName != null &&
                    this.TransInName.Equals(input.TransInName))
                ) && 
                (
                    this.TransInType == input.TransInType ||
                    (this.TransInType != null &&
                    this.TransInType.Equals(input.TransInType))
                ) && 
                (
                    this.TransOut == input.TransOut ||
                    (this.TransOut != null &&
                    this.TransOut.Equals(input.TransOut))
                ) && 
                (
                    this.TransOutType == input.TransOutType ||
                    (this.TransOutType != null &&
                    this.TransOutType.Equals(input.TransOutType))
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
                if (this.Amount != null)
                {
                    hashCode = (hashCode * 59) + this.Amount.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.AmountPercentage.GetHashCode();
                if (this.Desc != null)
                {
                    hashCode = (hashCode * 59) + this.Desc.GetHashCode();
                }
                if (this.RoyaltyScene != null)
                {
                    hashCode = (hashCode * 59) + this.RoyaltyScene.GetHashCode();
                }
                if (this.RoyaltyType != null)
                {
                    hashCode = (hashCode * 59) + this.RoyaltyType.GetHashCode();
                }
                if (this.TransIn != null)
                {
                    hashCode = (hashCode * 59) + this.TransIn.GetHashCode();
                }
                if (this.TransInName != null)
                {
                    hashCode = (hashCode * 59) + this.TransInName.GetHashCode();
                }
                if (this.TransInType != null)
                {
                    hashCode = (hashCode * 59) + this.TransInType.GetHashCode();
                }
                if (this.TransOut != null)
                {
                    hashCode = (hashCode * 59) + this.TransOut.GetHashCode();
                }
                if (this.TransOutType != null)
                {
                    hashCode = (hashCode * 59) + this.TransOutType.GetHashCode();
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
