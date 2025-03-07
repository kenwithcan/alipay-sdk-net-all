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
    /// EnterpriseTitleInfo
    /// </summary>
    [DataContract(Name = "EnterpriseTitleInfo")]
    public partial class EnterpriseTitleInfo : IEquatable<EnterpriseTitleInfo>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="EnterpriseTitleInfo" /> class.
        /// </summary>
        /// <param name="address">详细地址.</param>
        /// <param name="bankAccount">开户行账号.</param>
        /// <param name="bankName">开户行地址.</param>
        /// <param name="taxRegisterNo">税号.</param>
        /// <param name="telephone">电话.</param>
        /// <param name="titleId">抬头ID.</param>
        /// <param name="titleName">企业抬头名称.</param>
        public EnterpriseTitleInfo(string address = default(string), string bankAccount = default(string), string bankName = default(string), string taxRegisterNo = default(string), string telephone = default(string), string titleId = default(string), string titleName = default(string))
        {
            this.Address = address;
            this.BankAccount = bankAccount;
            this.BankName = bankName;
            this.TaxRegisterNo = taxRegisterNo;
            this.Telephone = telephone;
            this.TitleId = titleId;
            this.TitleName = titleName;
        }

        /// <summary>
        /// 详细地址
        /// </summary>
        /// <value>详细地址</value>
        [DataMember(Name = "address", EmitDefaultValue = false)]
        public string Address { get; set; }

        /// <summary>
        /// 开户行账号
        /// </summary>
        /// <value>开户行账号</value>
        [DataMember(Name = "bank_account", EmitDefaultValue = false)]
        public string BankAccount { get; set; }

        /// <summary>
        /// 开户行地址
        /// </summary>
        /// <value>开户行地址</value>
        [DataMember(Name = "bank_name", EmitDefaultValue = false)]
        public string BankName { get; set; }

        /// <summary>
        /// 税号
        /// </summary>
        /// <value>税号</value>
        [DataMember(Name = "tax_register_no", EmitDefaultValue = false)]
        public string TaxRegisterNo { get; set; }

        /// <summary>
        /// 电话
        /// </summary>
        /// <value>电话</value>
        [DataMember(Name = "telephone", EmitDefaultValue = false)]
        public string Telephone { get; set; }

        /// <summary>
        /// 抬头ID
        /// </summary>
        /// <value>抬头ID</value>
        [DataMember(Name = "title_id", EmitDefaultValue = false)]
        public string TitleId { get; set; }

        /// <summary>
        /// 企业抬头名称
        /// </summary>
        /// <value>企业抬头名称</value>
        [DataMember(Name = "title_name", EmitDefaultValue = false)]
        public string TitleName { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class EnterpriseTitleInfo {\n");
            sb.Append("  Address: ").Append(Address).Append("\n");
            sb.Append("  BankAccount: ").Append(BankAccount).Append("\n");
            sb.Append("  BankName: ").Append(BankName).Append("\n");
            sb.Append("  TaxRegisterNo: ").Append(TaxRegisterNo).Append("\n");
            sb.Append("  Telephone: ").Append(Telephone).Append("\n");
            sb.Append("  TitleId: ").Append(TitleId).Append("\n");
            sb.Append("  TitleName: ").Append(TitleName).Append("\n");
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
            return this.Equals(input as EnterpriseTitleInfo);
        }

        /// <summary>
        /// Returns true if EnterpriseTitleInfo instances are equal
        /// </summary>
        /// <param name="input">Instance of EnterpriseTitleInfo to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(EnterpriseTitleInfo input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Address == input.Address ||
                    (this.Address != null &&
                    this.Address.Equals(input.Address))
                ) && 
                (
                    this.BankAccount == input.BankAccount ||
                    (this.BankAccount != null &&
                    this.BankAccount.Equals(input.BankAccount))
                ) && 
                (
                    this.BankName == input.BankName ||
                    (this.BankName != null &&
                    this.BankName.Equals(input.BankName))
                ) && 
                (
                    this.TaxRegisterNo == input.TaxRegisterNo ||
                    (this.TaxRegisterNo != null &&
                    this.TaxRegisterNo.Equals(input.TaxRegisterNo))
                ) && 
                (
                    this.Telephone == input.Telephone ||
                    (this.Telephone != null &&
                    this.Telephone.Equals(input.Telephone))
                ) && 
                (
                    this.TitleId == input.TitleId ||
                    (this.TitleId != null &&
                    this.TitleId.Equals(input.TitleId))
                ) && 
                (
                    this.TitleName == input.TitleName ||
                    (this.TitleName != null &&
                    this.TitleName.Equals(input.TitleName))
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
                if (this.Address != null)
                {
                    hashCode = (hashCode * 59) + this.Address.GetHashCode();
                }
                if (this.BankAccount != null)
                {
                    hashCode = (hashCode * 59) + this.BankAccount.GetHashCode();
                }
                if (this.BankName != null)
                {
                    hashCode = (hashCode * 59) + this.BankName.GetHashCode();
                }
                if (this.TaxRegisterNo != null)
                {
                    hashCode = (hashCode * 59) + this.TaxRegisterNo.GetHashCode();
                }
                if (this.Telephone != null)
                {
                    hashCode = (hashCode * 59) + this.Telephone.GetHashCode();
                }
                if (this.TitleId != null)
                {
                    hashCode = (hashCode * 59) + this.TitleId.GetHashCode();
                }
                if (this.TitleName != null)
                {
                    hashCode = (hashCode * 59) + this.TitleName.GetHashCode();
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
