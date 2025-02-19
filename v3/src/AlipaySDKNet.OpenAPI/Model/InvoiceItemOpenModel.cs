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
    /// InvoiceItemOpenModel
    /// </summary>
    [DataContract(Name = "InvoiceItemOpenModel")]
    public partial class InvoiceItemOpenModel : IEquatable<InvoiceItemOpenModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="InvoiceItemOpenModel" /> class.
        /// </summary>
        /// <param name="itemExTaxAmount">明细行不含税金额，单位元，保留两位小数.</param>
        /// <param name="itemName">开票项目：货物或应税劳务、服务名称.</param>
        /// <param name="itemNo">国税局制定的商品税收编码，必须是最末级.</param>
        /// <param name="itemQuantity">数量； 1.当row_type&#x3D;0或2且item_unit_price为空，可空； 2.可精确到小数点后6位.</param>
        /// <param name="itemSpec">规格型号.</param>
        /// <param name="itemSumAmount">明细行价税合计，单位元，必须保证item_sum_amount&#x3D;item_ex_tax_amount+item_tax_amount。.</param>
        /// <param name="itemTaxAmount">明细行税额，单位元，保留两位小数，无税或者免税情况下输入：0.00。.</param>
        /// <param name="itemTaxRate">明细行税率，无税或者免税情况下输入：0.00。.</param>
        /// <param name="itemUnit">单位.</param>
        /// <param name="itemUnitPrice">不含税单价（元）; 1.当row_type&#x3D;0或2且item_quantity为空，可空 2.可精确到小数点后8位；.</param>
        /// <param name="rowType">发票行性质：0表示正常行，1表示折扣行，2表示被折扣行。.</param>
        public InvoiceItemOpenModel(string itemExTaxAmount = default(string), string itemName = default(string), string itemNo = default(string), int itemQuantity = default(int), string itemSpec = default(string), string itemSumAmount = default(string), string itemTaxAmount = default(string), string itemTaxRate = default(string), string itemUnit = default(string), string itemUnitPrice = default(string), string rowType = default(string))
        {
            this.ItemExTaxAmount = itemExTaxAmount;
            this.ItemName = itemName;
            this.ItemNo = itemNo;
            this.ItemQuantity = itemQuantity;
            this.ItemSpec = itemSpec;
            this.ItemSumAmount = itemSumAmount;
            this.ItemTaxAmount = itemTaxAmount;
            this.ItemTaxRate = itemTaxRate;
            this.ItemUnit = itemUnit;
            this.ItemUnitPrice = itemUnitPrice;
            this.RowType = rowType;
        }

        /// <summary>
        /// 明细行不含税金额，单位元，保留两位小数
        /// </summary>
        /// <value>明细行不含税金额，单位元，保留两位小数</value>
        [DataMember(Name = "item_ex_tax_amount", EmitDefaultValue = false)]
        public string ItemExTaxAmount { get; set; }

        /// <summary>
        /// 开票项目：货物或应税劳务、服务名称
        /// </summary>
        /// <value>开票项目：货物或应税劳务、服务名称</value>
        [DataMember(Name = "item_name", EmitDefaultValue = false)]
        public string ItemName { get; set; }

        /// <summary>
        /// 国税局制定的商品税收编码，必须是最末级
        /// </summary>
        /// <value>国税局制定的商品税收编码，必须是最末级</value>
        [DataMember(Name = "item_no", EmitDefaultValue = false)]
        public string ItemNo { get; set; }

        /// <summary>
        /// 数量； 1.当row_type&#x3D;0或2且item_unit_price为空，可空； 2.可精确到小数点后6位
        /// </summary>
        /// <value>数量； 1.当row_type&#x3D;0或2且item_unit_price为空，可空； 2.可精确到小数点后6位</value>
        [DataMember(Name = "item_quantity", EmitDefaultValue = false)]
        public int ItemQuantity { get; set; }

        /// <summary>
        /// 规格型号
        /// </summary>
        /// <value>规格型号</value>
        [DataMember(Name = "item_spec", EmitDefaultValue = false)]
        public string ItemSpec { get; set; }

        /// <summary>
        /// 明细行价税合计，单位元，必须保证item_sum_amount&#x3D;item_ex_tax_amount+item_tax_amount。
        /// </summary>
        /// <value>明细行价税合计，单位元，必须保证item_sum_amount&#x3D;item_ex_tax_amount+item_tax_amount。</value>
        [DataMember(Name = "item_sum_amount", EmitDefaultValue = false)]
        public string ItemSumAmount { get; set; }

        /// <summary>
        /// 明细行税额，单位元，保留两位小数，无税或者免税情况下输入：0.00。
        /// </summary>
        /// <value>明细行税额，单位元，保留两位小数，无税或者免税情况下输入：0.00。</value>
        [DataMember(Name = "item_tax_amount", EmitDefaultValue = false)]
        public string ItemTaxAmount { get; set; }

        /// <summary>
        /// 明细行税率，无税或者免税情况下输入：0.00。
        /// </summary>
        /// <value>明细行税率，无税或者免税情况下输入：0.00。</value>
        [DataMember(Name = "item_tax_rate", EmitDefaultValue = false)]
        public string ItemTaxRate { get; set; }

        /// <summary>
        /// 单位
        /// </summary>
        /// <value>单位</value>
        [DataMember(Name = "item_unit", EmitDefaultValue = false)]
        public string ItemUnit { get; set; }

        /// <summary>
        /// 不含税单价（元）; 1.当row_type&#x3D;0或2且item_quantity为空，可空 2.可精确到小数点后8位；
        /// </summary>
        /// <value>不含税单价（元）; 1.当row_type&#x3D;0或2且item_quantity为空，可空 2.可精确到小数点后8位；</value>
        [DataMember(Name = "item_unit_price", EmitDefaultValue = false)]
        public string ItemUnitPrice { get; set; }

        /// <summary>
        /// 发票行性质：0表示正常行，1表示折扣行，2表示被折扣行。
        /// </summary>
        /// <value>发票行性质：0表示正常行，1表示折扣行，2表示被折扣行。</value>
        [DataMember(Name = "row_type", EmitDefaultValue = false)]
        public string RowType { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class InvoiceItemOpenModel {\n");
            sb.Append("  ItemExTaxAmount: ").Append(ItemExTaxAmount).Append("\n");
            sb.Append("  ItemName: ").Append(ItemName).Append("\n");
            sb.Append("  ItemNo: ").Append(ItemNo).Append("\n");
            sb.Append("  ItemQuantity: ").Append(ItemQuantity).Append("\n");
            sb.Append("  ItemSpec: ").Append(ItemSpec).Append("\n");
            sb.Append("  ItemSumAmount: ").Append(ItemSumAmount).Append("\n");
            sb.Append("  ItemTaxAmount: ").Append(ItemTaxAmount).Append("\n");
            sb.Append("  ItemTaxRate: ").Append(ItemTaxRate).Append("\n");
            sb.Append("  ItemUnit: ").Append(ItemUnit).Append("\n");
            sb.Append("  ItemUnitPrice: ").Append(ItemUnitPrice).Append("\n");
            sb.Append("  RowType: ").Append(RowType).Append("\n");
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
            return this.Equals(input as InvoiceItemOpenModel);
        }

        /// <summary>
        /// Returns true if InvoiceItemOpenModel instances are equal
        /// </summary>
        /// <param name="input">Instance of InvoiceItemOpenModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(InvoiceItemOpenModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.ItemExTaxAmount == input.ItemExTaxAmount ||
                    (this.ItemExTaxAmount != null &&
                    this.ItemExTaxAmount.Equals(input.ItemExTaxAmount))
                ) && 
                (
                    this.ItemName == input.ItemName ||
                    (this.ItemName != null &&
                    this.ItemName.Equals(input.ItemName))
                ) && 
                (
                    this.ItemNo == input.ItemNo ||
                    (this.ItemNo != null &&
                    this.ItemNo.Equals(input.ItemNo))
                ) && 
                (
                    this.ItemQuantity == input.ItemQuantity ||
                    this.ItemQuantity.Equals(input.ItemQuantity)
                ) && 
                (
                    this.ItemSpec == input.ItemSpec ||
                    (this.ItemSpec != null &&
                    this.ItemSpec.Equals(input.ItemSpec))
                ) && 
                (
                    this.ItemSumAmount == input.ItemSumAmount ||
                    (this.ItemSumAmount != null &&
                    this.ItemSumAmount.Equals(input.ItemSumAmount))
                ) && 
                (
                    this.ItemTaxAmount == input.ItemTaxAmount ||
                    (this.ItemTaxAmount != null &&
                    this.ItemTaxAmount.Equals(input.ItemTaxAmount))
                ) && 
                (
                    this.ItemTaxRate == input.ItemTaxRate ||
                    (this.ItemTaxRate != null &&
                    this.ItemTaxRate.Equals(input.ItemTaxRate))
                ) && 
                (
                    this.ItemUnit == input.ItemUnit ||
                    (this.ItemUnit != null &&
                    this.ItemUnit.Equals(input.ItemUnit))
                ) && 
                (
                    this.ItemUnitPrice == input.ItemUnitPrice ||
                    (this.ItemUnitPrice != null &&
                    this.ItemUnitPrice.Equals(input.ItemUnitPrice))
                ) && 
                (
                    this.RowType == input.RowType ||
                    (this.RowType != null &&
                    this.RowType.Equals(input.RowType))
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
                if (this.ItemExTaxAmount != null)
                {
                    hashCode = (hashCode * 59) + this.ItemExTaxAmount.GetHashCode();
                }
                if (this.ItemName != null)
                {
                    hashCode = (hashCode * 59) + this.ItemName.GetHashCode();
                }
                if (this.ItemNo != null)
                {
                    hashCode = (hashCode * 59) + this.ItemNo.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.ItemQuantity.GetHashCode();
                if (this.ItemSpec != null)
                {
                    hashCode = (hashCode * 59) + this.ItemSpec.GetHashCode();
                }
                if (this.ItemSumAmount != null)
                {
                    hashCode = (hashCode * 59) + this.ItemSumAmount.GetHashCode();
                }
                if (this.ItemTaxAmount != null)
                {
                    hashCode = (hashCode * 59) + this.ItemTaxAmount.GetHashCode();
                }
                if (this.ItemTaxRate != null)
                {
                    hashCode = (hashCode * 59) + this.ItemTaxRate.GetHashCode();
                }
                if (this.ItemUnit != null)
                {
                    hashCode = (hashCode * 59) + this.ItemUnit.GetHashCode();
                }
                if (this.ItemUnitPrice != null)
                {
                    hashCode = (hashCode * 59) + this.ItemUnitPrice.GetHashCode();
                }
                if (this.RowType != null)
                {
                    hashCode = (hashCode * 59) + this.RowType.GetHashCode();
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
