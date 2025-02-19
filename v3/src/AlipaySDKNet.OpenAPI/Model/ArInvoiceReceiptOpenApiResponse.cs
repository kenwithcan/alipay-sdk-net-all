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
    /// ArInvoiceReceiptOpenApiResponse
    /// </summary>
    [DataContract(Name = "ArInvoiceReceiptOpenApiResponse")]
    public partial class ArInvoiceReceiptOpenApiResponse : IEquatable<ArInvoiceReceiptOpenApiResponse>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ArInvoiceReceiptOpenApiResponse" /> class.
        /// </summary>
        /// <param name="arrangementNo">合约号.</param>
        /// <param name="id">可开票单据主键ID.</param>
        /// <param name="instId">机构ID.</param>
        /// <param name="invDt">开票时间 格式：yyyymm.</param>
        /// <param name="invMode">开票模式  01：实收开票， 02：应收开票， 03：累计实收开票.</param>
        /// <param name="invoiceAmt">invoiceAmt.</param>
        /// <param name="invoicedAmt">invoicedAmt.</param>
        /// <param name="ipId">结算ip_id.</param>
        /// <param name="ipRoleId">结算对象ip_role_id.</param>
        /// <param name="lastModer">最后修改人.</param>
        /// <param name="linkInvoiceAmt">linkInvoiceAmt.</param>
        /// <param name="outBizNo">外部单据号，对应开票记录的月账单号.</param>
        /// <param name="outBizType">可开票单据来源，01：主站，02：芝麻，03：金融云，04：微贷.</param>
        /// <param name="payWay">付款方式，1：资金，5：走量.</param>
        /// <param name="prodCode">产品码.</param>
        /// <param name="settleType">结算类型 ，01：实时，02：预收，03：后收，04：周期性，05：按日汇总，09：延期结算.</param>
        /// <param name="status">开票金额消耗状态：01未开票，02部分开票，03：已开票.</param>
        /// <param name="taxRate">税率.</param>
        /// <param name="taxType">税收类型01：增值税，02：营业税.</param>
        /// <param name="tntInstId">租户ID.</param>
        /// <param name="type">类型，1：应收，2：返点.</param>
        public ArInvoiceReceiptOpenApiResponse(string arrangementNo = default(string), string id = default(string), string instId = default(string), string invDt = default(string), string invMode = default(string), MultiCurrencyMoneyOpenApi invoiceAmt = default(MultiCurrencyMoneyOpenApi), MultiCurrencyMoneyOpenApi invoicedAmt = default(MultiCurrencyMoneyOpenApi), string ipId = default(string), string ipRoleId = default(string), string lastModer = default(string), MultiCurrencyMoneyOpenApi linkInvoiceAmt = default(MultiCurrencyMoneyOpenApi), string outBizNo = default(string), string outBizType = default(string), string payWay = default(string), string prodCode = default(string), string settleType = default(string), string status = default(string), int taxRate = default(int), string taxType = default(string), string tntInstId = default(string), string type = default(string))
        {
            this.ArrangementNo = arrangementNo;
            this.Id = id;
            this.InstId = instId;
            this.InvDt = invDt;
            this.InvMode = invMode;
            this.InvoiceAmt = invoiceAmt;
            this.InvoicedAmt = invoicedAmt;
            this.IpId = ipId;
            this.IpRoleId = ipRoleId;
            this.LastModer = lastModer;
            this.LinkInvoiceAmt = linkInvoiceAmt;
            this.OutBizNo = outBizNo;
            this.OutBizType = outBizType;
            this.PayWay = payWay;
            this.ProdCode = prodCode;
            this.SettleType = settleType;
            this.Status = status;
            this.TaxRate = taxRate;
            this.TaxType = taxType;
            this.TntInstId = tntInstId;
            this.Type = type;
        }

        /// <summary>
        /// 合约号
        /// </summary>
        /// <value>合约号</value>
        [DataMember(Name = "arrangement_no", EmitDefaultValue = false)]
        public string ArrangementNo { get; set; }

        /// <summary>
        /// 可开票单据主键ID
        /// </summary>
        /// <value>可开票单据主键ID</value>
        [DataMember(Name = "id", EmitDefaultValue = false)]
        public string Id { get; set; }

        /// <summary>
        /// 机构ID
        /// </summary>
        /// <value>机构ID</value>
        [DataMember(Name = "inst_id", EmitDefaultValue = false)]
        public string InstId { get; set; }

        /// <summary>
        /// 开票时间 格式：yyyymm
        /// </summary>
        /// <value>开票时间 格式：yyyymm</value>
        [DataMember(Name = "inv_dt", EmitDefaultValue = false)]
        public string InvDt { get; set; }

        /// <summary>
        /// 开票模式  01：实收开票， 02：应收开票， 03：累计实收开票
        /// </summary>
        /// <value>开票模式  01：实收开票， 02：应收开票， 03：累计实收开票</value>
        [DataMember(Name = "inv_mode", EmitDefaultValue = false)]
        public string InvMode { get; set; }

        /// <summary>
        /// Gets or Sets InvoiceAmt
        /// </summary>
        [DataMember(Name = "invoice_amt", EmitDefaultValue = false)]
        public MultiCurrencyMoneyOpenApi InvoiceAmt { get; set; }

        /// <summary>
        /// Gets or Sets InvoicedAmt
        /// </summary>
        [DataMember(Name = "invoiced_amt", EmitDefaultValue = false)]
        public MultiCurrencyMoneyOpenApi InvoicedAmt { get; set; }

        /// <summary>
        /// 结算ip_id
        /// </summary>
        /// <value>结算ip_id</value>
        [DataMember(Name = "ip_id", EmitDefaultValue = false)]
        public string IpId { get; set; }

        /// <summary>
        /// 结算对象ip_role_id
        /// </summary>
        /// <value>结算对象ip_role_id</value>
        [DataMember(Name = "ip_role_id", EmitDefaultValue = false)]
        public string IpRoleId { get; set; }

        /// <summary>
        /// 最后修改人
        /// </summary>
        /// <value>最后修改人</value>
        [DataMember(Name = "last_moder", EmitDefaultValue = false)]
        public string LastModer { get; set; }

        /// <summary>
        /// Gets or Sets LinkInvoiceAmt
        /// </summary>
        [DataMember(Name = "link_invoice_amt", EmitDefaultValue = false)]
        public MultiCurrencyMoneyOpenApi LinkInvoiceAmt { get; set; }

        /// <summary>
        /// 外部单据号，对应开票记录的月账单号
        /// </summary>
        /// <value>外部单据号，对应开票记录的月账单号</value>
        [DataMember(Name = "out_biz_no", EmitDefaultValue = false)]
        public string OutBizNo { get; set; }

        /// <summary>
        /// 可开票单据来源，01：主站，02：芝麻，03：金融云，04：微贷
        /// </summary>
        /// <value>可开票单据来源，01：主站，02：芝麻，03：金融云，04：微贷</value>
        [DataMember(Name = "out_biz_type", EmitDefaultValue = false)]
        public string OutBizType { get; set; }

        /// <summary>
        /// 付款方式，1：资金，5：走量
        /// </summary>
        /// <value>付款方式，1：资金，5：走量</value>
        [DataMember(Name = "pay_way", EmitDefaultValue = false)]
        public string PayWay { get; set; }

        /// <summary>
        /// 产品码
        /// </summary>
        /// <value>产品码</value>
        [DataMember(Name = "prod_code", EmitDefaultValue = false)]
        public string ProdCode { get; set; }

        /// <summary>
        /// 结算类型 ，01：实时，02：预收，03：后收，04：周期性，05：按日汇总，09：延期结算
        /// </summary>
        /// <value>结算类型 ，01：实时，02：预收，03：后收，04：周期性，05：按日汇总，09：延期结算</value>
        [DataMember(Name = "settle_type", EmitDefaultValue = false)]
        public string SettleType { get; set; }

        /// <summary>
        /// 开票金额消耗状态：01未开票，02部分开票，03：已开票
        /// </summary>
        /// <value>开票金额消耗状态：01未开票，02部分开票，03：已开票</value>
        [DataMember(Name = "status", EmitDefaultValue = false)]
        public string Status { get; set; }

        /// <summary>
        /// 税率
        /// </summary>
        /// <value>税率</value>
        [DataMember(Name = "tax_rate", EmitDefaultValue = false)]
        public int TaxRate { get; set; }

        /// <summary>
        /// 税收类型01：增值税，02：营业税
        /// </summary>
        /// <value>税收类型01：增值税，02：营业税</value>
        [DataMember(Name = "tax_type", EmitDefaultValue = false)]
        public string TaxType { get; set; }

        /// <summary>
        /// 租户ID
        /// </summary>
        /// <value>租户ID</value>
        [DataMember(Name = "tnt_inst_id", EmitDefaultValue = false)]
        public string TntInstId { get; set; }

        /// <summary>
        /// 类型，1：应收，2：返点
        /// </summary>
        /// <value>类型，1：应收，2：返点</value>
        [DataMember(Name = "type", EmitDefaultValue = false)]
        public string Type { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class ArInvoiceReceiptOpenApiResponse {\n");
            sb.Append("  ArrangementNo: ").Append(ArrangementNo).Append("\n");
            sb.Append("  Id: ").Append(Id).Append("\n");
            sb.Append("  InstId: ").Append(InstId).Append("\n");
            sb.Append("  InvDt: ").Append(InvDt).Append("\n");
            sb.Append("  InvMode: ").Append(InvMode).Append("\n");
            sb.Append("  InvoiceAmt: ").Append(InvoiceAmt).Append("\n");
            sb.Append("  InvoicedAmt: ").Append(InvoicedAmt).Append("\n");
            sb.Append("  IpId: ").Append(IpId).Append("\n");
            sb.Append("  IpRoleId: ").Append(IpRoleId).Append("\n");
            sb.Append("  LastModer: ").Append(LastModer).Append("\n");
            sb.Append("  LinkInvoiceAmt: ").Append(LinkInvoiceAmt).Append("\n");
            sb.Append("  OutBizNo: ").Append(OutBizNo).Append("\n");
            sb.Append("  OutBizType: ").Append(OutBizType).Append("\n");
            sb.Append("  PayWay: ").Append(PayWay).Append("\n");
            sb.Append("  ProdCode: ").Append(ProdCode).Append("\n");
            sb.Append("  SettleType: ").Append(SettleType).Append("\n");
            sb.Append("  Status: ").Append(Status).Append("\n");
            sb.Append("  TaxRate: ").Append(TaxRate).Append("\n");
            sb.Append("  TaxType: ").Append(TaxType).Append("\n");
            sb.Append("  TntInstId: ").Append(TntInstId).Append("\n");
            sb.Append("  Type: ").Append(Type).Append("\n");
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
            return this.Equals(input as ArInvoiceReceiptOpenApiResponse);
        }

        /// <summary>
        /// Returns true if ArInvoiceReceiptOpenApiResponse instances are equal
        /// </summary>
        /// <param name="input">Instance of ArInvoiceReceiptOpenApiResponse to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(ArInvoiceReceiptOpenApiResponse input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.ArrangementNo == input.ArrangementNo ||
                    (this.ArrangementNo != null &&
                    this.ArrangementNo.Equals(input.ArrangementNo))
                ) && 
                (
                    this.Id == input.Id ||
                    (this.Id != null &&
                    this.Id.Equals(input.Id))
                ) && 
                (
                    this.InstId == input.InstId ||
                    (this.InstId != null &&
                    this.InstId.Equals(input.InstId))
                ) && 
                (
                    this.InvDt == input.InvDt ||
                    (this.InvDt != null &&
                    this.InvDt.Equals(input.InvDt))
                ) && 
                (
                    this.InvMode == input.InvMode ||
                    (this.InvMode != null &&
                    this.InvMode.Equals(input.InvMode))
                ) && 
                (
                    this.InvoiceAmt == input.InvoiceAmt ||
                    (this.InvoiceAmt != null &&
                    this.InvoiceAmt.Equals(input.InvoiceAmt))
                ) && 
                (
                    this.InvoicedAmt == input.InvoicedAmt ||
                    (this.InvoicedAmt != null &&
                    this.InvoicedAmt.Equals(input.InvoicedAmt))
                ) && 
                (
                    this.IpId == input.IpId ||
                    (this.IpId != null &&
                    this.IpId.Equals(input.IpId))
                ) && 
                (
                    this.IpRoleId == input.IpRoleId ||
                    (this.IpRoleId != null &&
                    this.IpRoleId.Equals(input.IpRoleId))
                ) && 
                (
                    this.LastModer == input.LastModer ||
                    (this.LastModer != null &&
                    this.LastModer.Equals(input.LastModer))
                ) && 
                (
                    this.LinkInvoiceAmt == input.LinkInvoiceAmt ||
                    (this.LinkInvoiceAmt != null &&
                    this.LinkInvoiceAmt.Equals(input.LinkInvoiceAmt))
                ) && 
                (
                    this.OutBizNo == input.OutBizNo ||
                    (this.OutBizNo != null &&
                    this.OutBizNo.Equals(input.OutBizNo))
                ) && 
                (
                    this.OutBizType == input.OutBizType ||
                    (this.OutBizType != null &&
                    this.OutBizType.Equals(input.OutBizType))
                ) && 
                (
                    this.PayWay == input.PayWay ||
                    (this.PayWay != null &&
                    this.PayWay.Equals(input.PayWay))
                ) && 
                (
                    this.ProdCode == input.ProdCode ||
                    (this.ProdCode != null &&
                    this.ProdCode.Equals(input.ProdCode))
                ) && 
                (
                    this.SettleType == input.SettleType ||
                    (this.SettleType != null &&
                    this.SettleType.Equals(input.SettleType))
                ) && 
                (
                    this.Status == input.Status ||
                    (this.Status != null &&
                    this.Status.Equals(input.Status))
                ) && 
                (
                    this.TaxRate == input.TaxRate ||
                    this.TaxRate.Equals(input.TaxRate)
                ) && 
                (
                    this.TaxType == input.TaxType ||
                    (this.TaxType != null &&
                    this.TaxType.Equals(input.TaxType))
                ) && 
                (
                    this.TntInstId == input.TntInstId ||
                    (this.TntInstId != null &&
                    this.TntInstId.Equals(input.TntInstId))
                ) && 
                (
                    this.Type == input.Type ||
                    (this.Type != null &&
                    this.Type.Equals(input.Type))
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
                if (this.ArrangementNo != null)
                {
                    hashCode = (hashCode * 59) + this.ArrangementNo.GetHashCode();
                }
                if (this.Id != null)
                {
                    hashCode = (hashCode * 59) + this.Id.GetHashCode();
                }
                if (this.InstId != null)
                {
                    hashCode = (hashCode * 59) + this.InstId.GetHashCode();
                }
                if (this.InvDt != null)
                {
                    hashCode = (hashCode * 59) + this.InvDt.GetHashCode();
                }
                if (this.InvMode != null)
                {
                    hashCode = (hashCode * 59) + this.InvMode.GetHashCode();
                }
                if (this.InvoiceAmt != null)
                {
                    hashCode = (hashCode * 59) + this.InvoiceAmt.GetHashCode();
                }
                if (this.InvoicedAmt != null)
                {
                    hashCode = (hashCode * 59) + this.InvoicedAmt.GetHashCode();
                }
                if (this.IpId != null)
                {
                    hashCode = (hashCode * 59) + this.IpId.GetHashCode();
                }
                if (this.IpRoleId != null)
                {
                    hashCode = (hashCode * 59) + this.IpRoleId.GetHashCode();
                }
                if (this.LastModer != null)
                {
                    hashCode = (hashCode * 59) + this.LastModer.GetHashCode();
                }
                if (this.LinkInvoiceAmt != null)
                {
                    hashCode = (hashCode * 59) + this.LinkInvoiceAmt.GetHashCode();
                }
                if (this.OutBizNo != null)
                {
                    hashCode = (hashCode * 59) + this.OutBizNo.GetHashCode();
                }
                if (this.OutBizType != null)
                {
                    hashCode = (hashCode * 59) + this.OutBizType.GetHashCode();
                }
                if (this.PayWay != null)
                {
                    hashCode = (hashCode * 59) + this.PayWay.GetHashCode();
                }
                if (this.ProdCode != null)
                {
                    hashCode = (hashCode * 59) + this.ProdCode.GetHashCode();
                }
                if (this.SettleType != null)
                {
                    hashCode = (hashCode * 59) + this.SettleType.GetHashCode();
                }
                if (this.Status != null)
                {
                    hashCode = (hashCode * 59) + this.Status.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.TaxRate.GetHashCode();
                if (this.TaxType != null)
                {
                    hashCode = (hashCode * 59) + this.TaxType.GetHashCode();
                }
                if (this.TntInstId != null)
                {
                    hashCode = (hashCode * 59) + this.TntInstId.GetHashCode();
                }
                if (this.Type != null)
                {
                    hashCode = (hashCode * 59) + this.Type.GetHashCode();
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
