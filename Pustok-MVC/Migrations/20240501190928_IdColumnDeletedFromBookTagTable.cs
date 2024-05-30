using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Pustok_MVC.Migrations
{
    public partial class IdColumnDeletedFromBookTagTable : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropPrimaryKey(
                name: "PK_BookTags",
                table: "BookTags");

            migrationBuilder.DropIndex(
                name: "IX_BookTags_BookId",
                table: "BookTags");

            migrationBuilder.DropColumn(
                name: "Id",
                table: "BookTags");

            migrationBuilder.AddPrimaryKey(
                name: "PK_BookTags",
                table: "BookTags",
                columns: new[] { "BookId", "TagId" });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropPrimaryKey(
                name: "PK_BookTags",
                table: "BookTags");

            migrationBuilder.AddColumn<int>(
                name: "Id",
                table: "BookTags",
                type: "int",
                nullable: false,
                defaultValue: 0)
                .Annotation("SqlServer:Identity", "1, 1");

            migrationBuilder.AddPrimaryKey(
                name: "PK_BookTags",
                table: "BookTags",
                column: "Id");

            migrationBuilder.CreateIndex(
                name: "IX_BookTags_BookId",
                table: "BookTags",
                column: "BookId");
        }
    }
}
